FROM python:alpine3.16
RUN apk update
RUN apk upgrade
RUN apk add build-base
RUN apk add socat
RUN pip install pycryptodome sympy

RUN adduser -h /home/somebody -s /bin/bash ctf -u 1001 | echo ctf | echo ctf

WORKDIR /home/ctf

COPY flag .
COPY main.py .
USER ctf

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"python3.11 main.py "
