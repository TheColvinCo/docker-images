FROM php:8.0-fpm-alpine3.13

ONBUILD ARG DATADOG_VERSION=0.52.0
ONBUILD ARG INSTALL_DATADOG=false

# persistent / runtime deps
RUN apk add --no-cache \
		acl \
		fcgi \
		file \
		gettext \
		git \
		coreutils \
	;

# INSTALL PHP DEPENDENCIES
COPY --from=mlocati/php-extension-installer /usr/bin/install-php-extensions /usr/bin/install-php-extensions
RUN install-php-extensions intl pcntl pdo_mysql zip apcu opcache redis curl amqp

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

RUN ln -s $PHP_INI_DIR/php.ini-production $PHP_INI_DIR/php.ini
COPY ./rootfs/usr/local/etc/php/conf.d/api-platform.prod.ini $PHP_INI_DIR/conf.d/api-platform.ini
COPY ./rootfs/usr/local/etc/php-fpm.d/zz-docker.conf /usr/local/etc/php-fpm.d/zz-docker.conf

RUN set -eux; \
	{ \
		echo '[www]'; \
		echo 'ping.path = /ping'; \
	} | tee /usr/local/etc/php-fpm.d/docker-healthcheck.conf

# https://getcomposer.org/doc/03-cli.md#composer-allow-superuser
ENV COMPOSER_ALLOW_SUPERUSER=1
# install Symfony Flex globally to speed up download of Composer packages (parallelized prefetching)
RUN set -eux; \
	composer global require "symfony/flex" --prefer-dist --no-progress --classmap-authoritative; \
	composer clear-cache
ENV PATH="${PATH}:/root/.composer/vendor/bin"

WORKDIR /srv/api

# build for production
ARG APP_ENV=prod

# Datadog
ONBUILD RUN if [ "$INSTALL_DATADOG" = "true" ] ; then wget https://github.com/DataDog/dd-trace-php/releases/download/$DATADOG_VERSION/datadog-php-tracer_${DATADOG_VERSION}_noarch.apk -O datadog-php-tracer.apk \
      && apk add datadog-php-tracer.apk --allow-untrusted \
      && rm datadog-php-tracer.apk; fi

# prevent the reinstallation of vendors at every changes in the source code
ONBUILD COPY composer.json composer.lock symfony.lock ./
ONBUILD RUN set -eux; \
	composer install --prefer-dist --no-dev --no-scripts --no-progress --ignore-platform-reqs; \
	composer clear-cache

# do not use .env files in production
ONBUILD COPY .env ./
ONBUILD RUN composer dump-env prod; \
	rm .env

# copy only specifically what we need
ONBUILD COPY bin bin/
ONBUILD COPY config config/
ONBUILD COPY migrations migrations/
ONBUILD COPY public public/
ONBUILD COPY src src/

ONBUILD RUN set -eux; \
	mkdir -p var/cache var/log; \
	composer dump-autoload --classmap-authoritative --no-dev; \
	composer run-script --no-dev post-install-cmd; \
	chmod +x bin/console; sync
VOLUME /srv/api/var

COPY docker-healthcheck.sh /usr/local/bin/docker-healthcheck
RUN chmod +x /usr/local/bin/docker-healthcheck

HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD ["docker-healthcheck"]

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint
RUN chmod +x /usr/local/bin/docker-entrypoint

ENTRYPOINT ["docker-entrypoint"]
CMD ["php-fpm"]
