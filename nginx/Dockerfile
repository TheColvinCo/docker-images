FROM openresty/openresty:1.17.8.1-alpine

COPY conf/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY conf/conf.d/default.conf /etc/nginx/conf.d/default.conf

WORKDIR /srv/api/public