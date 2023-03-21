FROM ubuntu AS app

FROM pwn.red/jail
COPY --from=app / /srv

COPY main /srv/app/run
COPY flag.txt /srv/app/flag.txt
COPY ld-2.33.so /srv/app/ld-2.33.so
COPY libc.so.6 /srv/app/libc.so.6


