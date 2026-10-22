// Package traefik_plugin_secure_cookies is a Traefik middleware that adds the Secure attribute to
// every Set-Cookie response header that lacks it.
package traefik_plugin_secure_cookies

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
)

const (
	setCookieHeader          = "Set-Cookie"
	contentLengthHeader      = "Content-Length"
	secureAttributeName      = "Secure"
	attributeSeparator       = ";"
	attributeValueSeparator  = "="
	secureAttributeSuffix    = attributeSeparator + " " + secureAttributeName
	trailingSeparatorPadding = attributeSeparator + " \t"
)

var errHijackNotSupported = errors.New("the underlying response writer does not support hijacking")

// Config is the plugin configuration. The middleware has no options.
type Config struct{}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// SecureCookies is the middleware handler.
type SecureCookies struct {
	next http.Handler
}

// New creates the middleware.
func New(_ context.Context, next http.Handler, _ *Config, _ string) (http.Handler, error) {
	return &SecureCookies{next: next}, nil
}

func (middleware *SecureCookies) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	middleware.next.ServeHTTP(&secureCookieResponseWriter{ResponseWriter: responseWriter}, request)
}

type secureCookieResponseWriter struct {
	http.ResponseWriter
	finalHeadersSent bool
}

func (writer *secureCookieResponseWriter) WriteHeader(statusCode int) {
	writer.secureCookiesUnlessFinalHeadersSent()
	if !isInformational(statusCode) {
		writer.finalHeadersSent = true
	}
	writer.ResponseWriter.WriteHeader(statusCode)
}

// Yaegi hands compiled code, such as Traefik's reverse proxy, a wrapper of this writer that exposes
// Hijack but not Flush, so the proxy can never flush a streamed response through this middleware.
// Flushing after every write of a response of unknown length does what the proxy would have done:
// it flushes those responses immediately.
func (writer *secureCookieResponseWriter) Write(body []byte) (int, error) {
	writer.secureCookiesBeforeFinalHeadersLeave()
	writtenByteCount, err := writer.ResponseWriter.Write(body)
	if err == nil && writer.hasUnknownLength() {
		writer.flushUnderlyingWriter()
	}
	return writtenByteCount, err
}

func (writer *secureCookieResponseWriter) Flush() {
	writer.secureCookiesBeforeFinalHeadersLeave()
	writer.flushUnderlyingWriter()
}

func (writer *secureCookieResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	writer.secureCookiesBeforeFinalHeadersLeave()
	hijacker, isHijacker := writer.ResponseWriter.(http.Hijacker)
	if !isHijacker {
		return nil, nil, errHijackNotSupported
	}
	return hijacker.Hijack()
}

func (writer *secureCookieResponseWriter) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}

func (writer *secureCookieResponseWriter) hasUnknownLength() bool {
	return writer.Header().Get(contentLengthHeader) == ""
}

func (writer *secureCookieResponseWriter) flushUnderlyingWriter() {
	if flusher, isFlusher := writer.ResponseWriter.(http.Flusher); isFlusher {
		flusher.Flush()
	}
}

func (writer *secureCookieResponseWriter) secureCookiesBeforeFinalHeadersLeave() {
	writer.secureCookiesUnlessFinalHeadersSent()
	writer.finalHeadersSent = true
}

func (writer *secureCookieResponseWriter) secureCookiesUnlessFinalHeadersSent() {
	if !writer.finalHeadersSent {
		secureSetCookieHeaders(writer.Header())
	}
}

func isInformational(statusCode int) bool {
	return statusCode >= http.StatusContinue && statusCode < http.StatusOK && statusCode != http.StatusSwitchingProtocols
}

func secureSetCookieHeaders(header http.Header) {
	setCookieValues := header.Values(setCookieHeader)
	if len(setCookieValues) == 0 {
		return
	}
	securedValues := make([]string, len(setCookieValues))
	for index, setCookieValue := range setCookieValues {
		securedValues[index] = withSecureAttribute(setCookieValue)
	}
	header[http.CanonicalHeaderKey(setCookieHeader)] = securedValues
}

func withSecureAttribute(setCookieValue string) string {
	if strings.TrimSpace(setCookieValue) == "" || hasSecureAttribute(setCookieValue) {
		return setCookieValue
	}
	return strings.TrimRight(setCookieValue, trailingSeparatorPadding) + secureAttributeSuffix
}

func hasSecureAttribute(setCookieValue string) bool {
	_, attributes, _ := strings.Cut(setCookieValue, attributeSeparator)
	for _, attribute := range strings.Split(attributes, attributeSeparator) {
		attributeName, _, _ := strings.Cut(attribute, attributeValueSeparator)
		if strings.EqualFold(strings.TrimSpace(attributeName), secureAttributeName) {
			return true
		}
	}
	return false
}
