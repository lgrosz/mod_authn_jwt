# mod_authn_jwt

A JWT authentication module for Lighttpd.

This module provides a scheme handler in accordance with [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) and a backend in accordance with [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519).

## Requirements

- [lighttpd >= 1.4.75](https://redmine.lighttpd.net/)
- [libjwt >= 1.17.0](https://github.com/benmcollins/libjwt)


## Build

```sh
$ cmake -S path/to/source -B path/to/build -DLIGHTTPD_SOURCE_DIR=path/to/lighttpd-source -DLIGHTTPD_BUILD_DIR=path/to/lighttpd-build
$ cmake --build path/to/build
```

It is expected this project is built with the same artifacts (like config.h) as the lighttpd instance it'll be loaded into.

A builder is provided by the `builder` target in the root directory `Dockerfile`. A quick-build can be done like so

```sh
$ docker build path/to/repo --target=builder
```

## Usage

Load into lighttpd with the a code snippet like

```lighttpd-conf
server.modules += ( "mod_auth", "mod_authn_file", "mod_authn_jwt" )

auth.backend = "jwt"
auth.backend.jwt.opts = (
    "algorithm" => "RS256", # Algorithm which the token is signed
    "keyfile" => "/etc/ssl/public.pem", # The public key of the issuer
    "exp-leeway" => "300", # leeway in seconds for exp claim evaluation
    "nbf-leeway" => "300", # leeway in seconds for nbf claim evaluation
    "issuer" => "https://my-issuer.com", # iss claim is checked against this
    "subject" => "user123", # sub claim is checked against this
    "aud" => "https://my-client.com", # aud claim is checked against this

    # General claims can be achieved like so
    "claims" => (
      "int-claim" => 10,
      "str-claim" => "val"
    ),

    # Complex claims can be achieved like so
    "json-claims" => ("{\"nested\":{\"inner\": true}}")
)

auth.require = (
  "" => (
    "method" => "bearer",
    "realm" => "A realm",
    "require" => "valid-user"
  )
)
```

## Tests

Simply run `test.sh` from the `integration-test` directory, it will build and run everything itself.

```sh
$ cd path/to/repo/integration-test
path/to/repo/integration-test$ ./test.sh
```

Individual tests can be ran and inspected like...

```sh
path/to/repo/integration-test$ docker compose create --build
path/to/repo/integration-test$ docker start client
path/to/repo/integration-test$ docker exec client pytest test_jwt.py:test_invalidjwt
path/to/repo/integration-test$ docker logs server
path/to/repo/integration-test$ docker compose down --volumes
```
