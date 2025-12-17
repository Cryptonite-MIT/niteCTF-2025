FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    gcc \
    libc6-dev \
    socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY src.c /app/src.c
RUN gcc -o guardian src.c -lm


COPY flag.txt /app/flag.txt


RUN useradd -m ctf && chown -R ctf:ctf /app
USER ctf


EXPOSE 1337


CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:./guardian,pty,stderr,setsid"]
