FROM ubuntu AS app

RUN apt update
RUN apt install python3.10 -y

FROM pwn.red/jail
COPY --from=app / /srv
COPY main.py /srv/app/main.py
COPY flag /srv/app/flag.txt
COPY run.sh /srv/app/run

RUN mv /srv/app/flag.txt /srv/app/flag-$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 32).txt
