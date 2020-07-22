FROM opositatest/varnish-jwt:latest

COPY conf/default.vcl /etc/varnish/default.vcl

COPY docker-entrypoint.sh /
RUN chmod 744 /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["varnishd", "-F", "-f", "/etc/varnish/default.vcl", "-p", "http_resp_hdr_len=65536", "-p", "http_resp_size=98304"]