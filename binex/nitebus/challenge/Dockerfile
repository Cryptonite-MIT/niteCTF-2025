FROM ubuntu:22.04 AS app

RUN apt-get update && apt-get install -y qemu-user-static
RUN mkdir -p /app

COPY public/nitebus /app/nitebus
COPY flag.txt /app/flag.txt

RUN echo '#!/bin/sh\nexec /usr/bin/qemu-aarch64-static /app/nitebus' > /app/run

RUN chmod +x /app/run /app/nitebus

FROM pwn.red/jail

COPY --from=app / /srv

ENV JAIL_PIDS=50 JAIL_MEM=20M JAIL_TIME=200
