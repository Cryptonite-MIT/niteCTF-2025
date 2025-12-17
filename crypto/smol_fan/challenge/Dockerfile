FROM python:3.10-slim

WORKDIR /chal

RUN apt update && apt install -y socat && rm -rf /var/lib/apt/lists/*
RUN pip install ecdsa
RUN pip install sympy
RUN pip install gmpy2

COPY server.py  /chal/

ENV flag=nite{fake_flag}


CMD ["socat", "-T60", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:'python3 /chal/server.py'"]

