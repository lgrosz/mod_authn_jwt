# mod_authn_jwt

A JWT authentication module for Lighttpd.

[![CI](https://github.com/lgrosz/mod_authn_jwt/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/lgrosz/mod_authn_jwt/actions/workflows/ci.yml)

This module provides a scheme handler in accordance with [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) and a backend in accordance with [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519).

## Requirements

- [lighttpd >= 1.4.75](https://redmine.lighttpd.net/)
- [libjwt >= 3.1.0](https://github.com/benmcollins/libjwt)


## Build

The build is performed by patching the source into and building lighttpd. All build systems supported by lighttpd are supported by this module.

Begin by patching the source

```sh
$ cp mod_authn_jwt/mod_authn_file.c lighttpd/src
$ cp mod_authn_jwt/*.patch lighttpd
$ cd lighttpd
$ patch -p1 <CMakeLists.txt.patch
$ patch -p1 <meson.patch
$ patch -p1 <autoconf.patch
```

Then configure and build with your preferred build system

### Autoconf

```sh
$ cd lighttpd
$ ./autogen.sh
$ ./configure --with-jwt
$ make
$ make check
```

### CMake

```sh
$ cmake -B build -S lighttpd -DWITH_JWT=ON
$ ctest --test-dir build
```

### Meson

```sh
$ meson setup -Dwith_jwt=enabled build lighttpd
$ ninja -C build
$ meson test -C build
```

### Docker

A `builder` and `tester` target in the root directory `Dockerfile` for quick-enough iteration without needing to setup a whole development environment.

```sh
$ docker build path/to/repo --target=builder
$ docker build path/to/repo --target=tester
```

## Usage

Load into lighttpd with the a code snippet like

```lighttpd-conf
server.modules += ( "mod_auth", "mod_authn_file", "mod_authn_jwt" )

auth.backend = "jwt"
auth.backend.jwt.opts = (
    "algorithm" => "RS256", # Algorithm which the token is signed
    "keyfile" => "/etc/ssl/jwk.json", # The public key of the issuer
    "exp-leeway" => "300", # leeway in seconds for exp claim evaluation
    "nbf-leeway" => "300", # leeway in seconds for nbf claim evaluation
    "audience" => "https://my-client.com", # aud claim is checked against this
    "issuer" => "https://my-issuer.com", # iss claim is checked against this
    "subject" => "user123", # sub claim is checked against this
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
path/to/repo/integration-test$ docker compose start client
path/to/repo/integration-test$ docker compose exec client pytest test_jwt.py::test_invalidjwt
path/to/repo/integration-test$ docker compose logs server
path/to/repo/integration-test$ docker compose down --volumes
```
