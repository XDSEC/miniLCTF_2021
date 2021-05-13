FROM python:3.7-alpine

RUN mkdir /app

COPY minil1 /app

RUN pip install -i http://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com --no-cache-dir flask

COPY ./start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]

EXPOSE 5000
