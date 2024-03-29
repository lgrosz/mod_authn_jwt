#!/bin/sh

docker compose up --build --detach

docker compose exec client pytest
code=$?

docker compose down --volumes

exit $code
