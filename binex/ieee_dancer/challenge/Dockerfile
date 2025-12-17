FROM ubuntu:22.04 AS app
RUN rm -rf /var/lib/apt/lists/*

RUN mkdir -p /challenge
WORKDIR /challenge
COPY chall .
COPY flag .

FROM pwn.red/jail

COPY --from=app / /srv
RUN mkdir -p /srv/app
COPY --chmod=555 ./run /srv/app/run

ENV JAIL_PIDS=50 JAIL_MEM=5M JAIL_TIME=200

