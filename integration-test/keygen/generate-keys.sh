#!/bin/sh

openssl genpkey -algorithm RSA -out /private/private.pem > /dev/null 2>&1
key2jwk -o /private/jwk.json /private/private.pem

openssl rsa -pubout -in /private/private.pem -out /public/public.pem > /dev/null 2>&1
key2jwk -o /public/jwk.json /public/public.pem
