FROM python:3.8-slim-buster

COPY start.sh /
RUN chmod 755 /start.sh
COPY app /app

WORKDIR /app

RUN pip install -i https://mirrors.aliyun.com/pypi/simple flask gunicorn[gevent] && \
    useradd -d /app web

ENTRYPOINT [ "/start.sh" ]
EXPOSE 5000
