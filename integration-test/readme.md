# Integration test

This directory contains integration tests. These tests are made up of three
parts

- The key generator, this generates a keypair which will be used to sign and
  verify tokens.
- The lighttpd server with mod_authn_jwt loaded, this is what is being tested.
  It must start after the key generator as mod_authn_jwt uses the public key to
  verify tokens.
- The client (the tester). This is a program will issue its own tokens, pass
  them through the server to assert on its response. It will do this for
  several tests.

