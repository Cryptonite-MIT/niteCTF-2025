FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3 \
    socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf

WORKDIR /home/ctf

COPY chall.py lottery.py roulette.py slotmachine.py secret.py ./

RUN chown -R root:root /home/ctf && \
    chmod -R 555 /home/ctf

USER ctf

ENV PORT=1337
ENV PYTHONUNBUFFERED=1 

EXPOSE $PORT

ENTRYPOINT socat TCP-LISTEN:${PORT},reuseaddr,fork EXEC:"python3 chall.py",stderr
