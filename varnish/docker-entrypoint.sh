#!/bin/sh
set -e

host=${BACKEND_HOST:-api}
environment=${ENV:-prod}

sed -i "s/%%BACKEND_HOST%%/$host/g" /etc/varnish/default.vcl
sed -i "s/%%ENV%%/$environment/g" /etc/varnish/default.vcl

exec "$@"
