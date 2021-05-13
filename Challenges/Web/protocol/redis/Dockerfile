FROM php:7.3.15-apache

RUN sed -i 's/http:\/\/archive.ubuntu.com\//http:\/\/mirrors.tuna.tsinghua.edu.cn\//g' /etc/apt/sources.list && \
    sed -i '/security/d' /etc/apt/sources.list
RUN apt-get -y update \
    && apt install -y gcc make cron

RUN  mkdir -p /usr/src/

COPY redis-3.2.11.tar.gz /usr/src

RUN cd /usr/src/ \
    &&  tar zxvf redis-3.2.11.tar.gz  \
    && cd /usr/src/redis-3.2.11/ \
    && make MALLOC=libc \
    && make install \
    && make clean \
    && cd /

RUN echo '<?php echo "flag就在这台机子上面，可是你怎么获得呢？";?>'> /var/www/html/index.php \
    && rm -f /var/www/html/index.html
COPY docker-entrypoint.sh /usr/local/bin/
RUN  chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 6379

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
