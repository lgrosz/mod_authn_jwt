#!/bin/sh

openssl genpkey -algorithm RSA -out /private/private.pem > /dev/null 2>&1
openssl rsa -pubout -in /private/private.pem -out /public/public.pem > /dev/null 2>&1
