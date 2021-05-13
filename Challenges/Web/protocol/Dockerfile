FROM php:7.3.15-apache

RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    echo 'Acquire::http:Proxy "http://202.117.124.9:8082";' > /etc/apt/apt.conf.d/proxy.conf && \
    apt update && apt install -y net-tools && rm -rf /var/lib/apt/lists/*

COPY index.php /var/www/html
WORKDIR /var/www/html
RUN echo '还是看看源码吧' > /flag

EXPOSE 80
