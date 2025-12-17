FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    socat \
    build-essential \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf

WORKDIR /home/ctf

RUN pip install --no-cache-dir pycryptodome gmpy2 sympy

COPY chal.py stronk_rabin_api.py ./

RUN chown -R root:root /home/ctf && \
    chmod -R 555 /home/ctf

USER ctf

ENV PORT=9999
ENV PYTHONBUFFERED=1

EXPOSE $PORT

ENTRYPOINT ["sh", "-c", "socat -T60 TCP-LISTEN:${PORT},reuseaddr,fork EXEC:'python3 -u chal.py',stderr"]
