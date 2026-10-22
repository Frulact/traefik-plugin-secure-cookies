# Secure Cookies

A Traefik middleware plugin that adds the `Secure` attribute to every `Set-Cookie` response header
that lacks it.

## Why

Some applications cannot be told to mark their cookies `Secure`. Self-hosted Dokploy, for one,
hard-codes `useSecureCookies: false` in its better-auth configuration
(`packages/server/src/lib/auth.ts`), so its session cookie reaches the browser without `Secure`
even though the panel is only served over HTTPS. Traefik's built-in middlewares can add, replace or
remove headers but cannot edit a `Set-Cookie` value, hence this plugin.

## What it does

Right before the response headers leave (on `WriteHeader`, the first `Write`, `Flush` or `Hijack`),
it looks at every `Set-Cookie` value:

- if one of its attributes is named `Secure` (in any letter case), the value is left as it is;
- otherwise `; Secure` is appended.

Only attribute names count: a cookie named `Secure`, a value `secure` or a path `/secure` does not.
Every other header, the status and the body are untouched. There are no options.

Informational responses (`103 Early Hints`) don't end the job: cookies of the final response are
secured too.

## Streaming and websockets

Websockets work: the wrapper hands `Hijack` to the underlying connection.

Streaming works too, with one twist. Traefik runs plugins in the Yaegi interpreter, and Yaegi can
only show Traefik's reverse proxy a response writer that hijacks or one that does neither; it has no
way to expose `Flush` as well. The proxy therefore cannot flush through any plugin that wraps the
response writer. To keep streamed responses (Server-Sent Events, chunked pages, live logs) arriving
as they are written, the plugin flushes after every write of a response without `Content-Length`,
which is what the proxy itself does for such responses. Responses with a `Content-Length` are not
flushed early.

Cookies that a reverse proxy copies onto a `101 Switching Protocols` response are not secured: Go's
reverse proxy copies them after it has hijacked the connection, when they no longer pass through a
middleware. Cookies set by middlewares before the upgrade are secured.

## Configuration

Static configuration:

```yaml
experimental:
  plugins:
    secureCookies:
      moduleName: github.com/Frulact/traefik-plugin-secure-cookies
      version: v0.1.0
```

Dynamic configuration:

```yaml
http:
  middlewares:
    secure-cookies:
      plugin:
        secureCookies: {}

  routers:
    my-router:
      rule: Host(`example.com`)
      middlewares:
        - secure-cookies
      service: my-service
```

Traefik downloads the plugin from `plugins.traefik.io` (which serves this repository's tag) every
time it starts. If the download fails, Traefik starts without any plugin, and every router that uses
`secure-cookies` fails to build and is left out.

## Development

The plugin uses the standard library only.

```sh
go test ./...
```

To run the tests the way Traefik runs the code, under Yaegi (the `Flush` tests are skipped there,
see above):

```sh
go install github.com/traefik/yaegi/cmd/yaegi@v0.16.1
mkdir -p "$(go env GOPATH)/src/github.com/Frulact"
ln -s "$PWD" "$(go env GOPATH)/src/github.com/Frulact/traefik-plugin-secure-cookies"
cd "$(go env GOPATH)/src/github.com/Frulact/traefik-plugin-secure-cookies"
GO111MODULE=off yaegi test -v .
```
