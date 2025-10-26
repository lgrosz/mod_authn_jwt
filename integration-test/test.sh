#!/bin/sh

docker compose run --build --rm client pytest
code=$?

docker compose down --volumes

exit $code
