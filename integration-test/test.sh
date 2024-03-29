#!/bin/sh

docker compose up --build --detach

docker compose exec client pytest

docker compose down --volumes
