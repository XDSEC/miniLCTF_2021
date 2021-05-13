FROM python:3.7-alpine

RUN adduser --disabled-password --gecos "" ctf

COPY bin /home/ctf
WORKDIR /home/ctf

USER ctf
CMD ["python", "task.py"]
