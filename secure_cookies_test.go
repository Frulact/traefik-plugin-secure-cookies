package traefik_plugin_secure_cookies

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const middlewareName = "secure-cookies"

type backendFunc func(http.ResponseWriter, *http.Request)

func (backend backendFunc) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	backend(writer, request)
}

const yaegiHidesFlush = "Yaegi hides Flush from code that receives this writer as an http.ResponseWriter"

type headerWriteStyle struct {
	name        string
	writeHeader func(*testing.T, http.ResponseWriter)
}

var headerWriteStyles = []headerWriteStyle{
	{
		name:        "explicit WriteHeader",
		writeHeader: func(_ *testing.T, writer http.ResponseWriter) { writer.WriteHeader(http.StatusOK) },
	},
	{
		name:        "implicit header on first Write",
		writeHeader: func(_ *testing.T, writer http.ResponseWriter) { _, _ = writer.Write([]byte("body")) },
	},
	{
		name: "Flush",
		writeHeader: func(t *testing.T, writer http.ResponseWriter) {
			flusher, isFlusher := writer.(http.Flusher)
			if !isFlusher {
				t.Skip(yaegiHidesFlush)
			}
			flusher.Flush()
		},
	},
}

func TestSetCookieHeadersAreSecured(t *testing.T) {
	testCases := []struct {
		name               string
		setCookieValues    []string
		expectedSetCookies []string
	}{
		{
			name:               "cookie without Secure gets it",
			setCookieValues:    []string{"session=abc; Path=/; HttpOnly; SameSite=Lax"},
			expectedSetCookies: []string{"session=abc; Path=/; HttpOnly; SameSite=Lax; Secure"},
		},
		{
			name:               "cookie with Secure stays untouched",
			setCookieValues:    []string{"session=abc; Path=/; Secure; HttpOnly"},
			expectedSetCookies: []string{"session=abc; Path=/; Secure; HttpOnly"},
		},
		{
			name:               "lower case secure attribute is recognised",
			setCookieValues:    []string{"session=abc; path=/; secure"},
			expectedSetCookies: []string{"session=abc; path=/; secure"},
		},
		{
			name:               "upper case secure attribute without spaces is recognised",
			setCookieValues:    []string{"session=abc;SECURE;HttpOnly"},
			expectedSetCookies: []string{"session=abc;SECURE;HttpOnly"},
		},
		{
			name:               "secure in the cookie value is not the attribute",
			setCookieValues:    []string{"mode=secure; Path=/"},
			expectedSetCookies: []string{"mode=secure; Path=/; Secure"},
		},
		{
			name:               "cookie named secure is not the attribute",
			setCookieValues:    []string{"Secure=1; Path=/"},
			expectedSetCookies: []string{"Secure=1; Path=/; Secure"},
		},
		{
			name:               "secure inside another attribute value is not the attribute",
			setCookieValues:    []string{"session=abc; Path=/secure; Domain=secure.example.com"},
			expectedSetCookies: []string{"session=abc; Path=/secure; Domain=secure.example.com; Secure"},
		},
		{
			name:               "cookie without attributes",
			setCookieValues:    []string{"session=abc"},
			expectedSetCookies: []string{"session=abc; Secure"},
		},
		{
			name:               "trailing separator is not doubled",
			setCookieValues:    []string{"session=abc; Path=/; "},
			expectedSetCookies: []string{"session=abc; Path=/; Secure"},
		},
		{
			name: "multiple cookies are each secured once",
			setCookieValues: []string{
				"better-auth.session_token=abc; Path=/; HttpOnly; SameSite=Lax",
				"theme=dark; Path=/; Secure",
				"better-auth.dont_remember=true; Max-Age=0",
			},
			expectedSetCookies: []string{
				"better-auth.session_token=abc; Path=/; HttpOnly; SameSite=Lax; Secure",
				"theme=dark; Path=/; Secure",
				"better-auth.dont_remember=true; Max-Age=0; Secure",
			},
		},
		{
			name:               "no cookies",
			setCookieValues:    nil,
			expectedSetCookies: nil,
		},
	}

	for _, style := range headerWriteStyles {
		for _, testCase := range testCases {
			t.Run(style.name+"/"+testCase.name, func(t *testing.T) {
				backend := backendFunc(func(writer http.ResponseWriter, _ *http.Request) {
					for _, setCookieValue := range testCase.setCookieValues {
						writer.Header().Add(setCookieHeader, setCookieValue)
					}
					style.writeHeader(t, writer)
				})

				recorder := serveThroughMiddleware(t, backend)

				assertSetCookies(t, recorder.Result().Header, testCase.expectedSetCookies)
			})
		}
	}
}

func TestOtherHeadersAndBodyStayUntouched(t *testing.T) {
	const body = "hello"
	backend := backendFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		writer.Header().Set("X-Secure", "no")
		writer.Header().Add(setCookieHeader, "session=abc")
		writer.WriteHeader(http.StatusTeapot)
		_, _ = writer.Write([]byte(body))
	})

	recorder := serveThroughMiddleware(t, backend)

	if recorder.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusTeapot)
	}
	if recorder.Body.String() != body {
		t.Errorf("body = %q, want %q", recorder.Body.String(), body)
	}
	if got := recorder.Header().Get("X-Secure"); got != "no" {
		t.Errorf("X-Secure = %q, want %q", got, "no")
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/plain" {
		t.Errorf("Content-Type = %q, want %q", got, "text/plain")
	}
}

func TestCookiesOfFinalResponseAreSecuredAfterInformationalResponse(t *testing.T) {
	backend := backendFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Add("Link", "</style.css>; rel=preload; as=style")
		writer.WriteHeader(http.StatusEarlyHints)
		writer.Header().Add(setCookieHeader, "session=abc; Path=/")
		writer.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(newMiddleware(t, backend))
	defer server.Close()

	response, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	assertSetCookies(t, response.Header, []string{"session=abc; Path=/; Secure"})
}

func TestFlushReachesUnderlyingWriter(t *testing.T) {
	backend := backendFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Add(setCookieHeader, "session=abc")
		err := http.NewResponseController(writer).Flush()
		if errors.Is(err, http.ErrNotSupported) {
			t.Skip(yaegiHidesFlush)
		}
		if err != nil {
			t.Errorf("Flush through response controller: %v", err)
		}
	})

	recorder := serveThroughMiddleware(t, backend)

	if !recorder.Flushed {
		t.Error("the underlying writer was not flushed")
	}
	assertSetCookies(t, recorder.Result().Header, []string{"session=abc; Secure"})
}

func TestWritesOfResponseWithUnknownLengthAreFlushed(t *testing.T) {
	backend := backendFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("first chunk"))
	})

	recorder := serveThroughMiddleware(t, backend)

	if !recorder.Flushed {
		t.Error("a write of a response with unknown length was not flushed")
	}
}

func TestWritesOfResponseWithKnownLengthAreNotFlushed(t *testing.T) {
	const body = "complete body"
	backend := backendFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set(contentLengthHeader, strconv.Itoa(len(body)))
		_, _ = writer.Write([]byte(body))
	})

	recorder := serveThroughMiddleware(t, backend)

	if recorder.Flushed {
		t.Error("a write of a response with known length was flushed")
	}
}

func TestHijackReachesUnderlyingConnectionWithSecuredCookies(t *testing.T) {
	const hijackedBody = "hijacked"
	backend := backendFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Add(setCookieHeader, "session=abc; Path=/")
		connection, buffer, err := http.NewResponseController(writer).Hijack()
		if err != nil {
			t.Errorf("Hijack through response controller: %v", err)
			return
		}
		defer connection.Close()
		writeRawResponse(t, buffer, writer.Header(), hijackedBody)
	})

	server := httptest.NewServer(newMiddleware(t, backend))
	defer server.Close()

	response, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	assertSetCookies(t, response.Header, []string{"session=abc; Path=/; Secure"})
	body, _ := io.ReadAll(response.Body)
	if string(body) != hijackedBody {
		t.Errorf("body = %q, want %q", body, hijackedBody)
	}
}

func TestHijackFailsWhenUnderlyingWriterCannotHijack(t *testing.T) {
	backend := backendFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _, err := writer.(http.Hijacker).Hijack()
		if !errors.Is(err, errHijackNotSupported) {
			t.Errorf("Hijack error = %v, want %v", err, errHijackNotSupported)
		}
	})

	serveThroughMiddleware(t, backend)
}

func newMiddleware(t *testing.T, backend http.Handler) http.Handler {
	t.Helper()
	middleware, err := New(context.Background(), backend, CreateConfig(), middlewareName)
	if err != nil {
		t.Fatal(err)
	}
	return middleware
}

func serveThroughMiddleware(t *testing.T, backend http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	newMiddleware(t, backend).ServeHTTP(recorder, request)
	return recorder
}

func writeRawResponse(t *testing.T, buffer *bufio.ReadWriter, header http.Header, body string) {
	t.Helper()
	response := &http.Response{
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
	}
	if err := response.Write(buffer); err != nil {
		t.Error(err)
	}
	if err := buffer.Flush(); err != nil {
		t.Error(err)
	}
}

func assertSetCookies(t *testing.T, header http.Header, expectedSetCookies []string) {
	t.Helper()
	if got := header.Values(setCookieHeader); !reflect.DeepEqual(got, expectedSetCookies) {
		t.Errorf("Set-Cookie = %q, want %q", got, expectedSetCookies)
	}
}
