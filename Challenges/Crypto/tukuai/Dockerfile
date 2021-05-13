FROM python:3.7-slim-buster

RUN adduser --disabled-password --gecos "" ctf

COPY bin /home/ctf
WORKDIR /home/ctf

RUN all_proxy=http://172.17.0.1:8082 pip install qiskit -i https://mirrors.aliyun.com/pypi/simple --no-cache-dir

USER ctf
CMD ["python", "task.py"]
