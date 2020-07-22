# Varnish

This image is based on opositatest/varnish-jwt to allow caching endpoint with enabled JWT.

The environment variable `PUBLIC_KEY` is needed to decrypt JWT tokens.

These environment variables can be set to change the behaviour of the provided VCL:

`BACKEND_HOST` (default to 'api')

`ENV` (default to 'prod')