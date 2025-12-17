FROM solanafoundation/solana-verifiable-build:2.3.5 as builder

WORKDIR /app

COPY sol-ctf-framework sol-ctf-framework
COPY server server
COPY program program

RUN cd server && cargo build --release

RUN cd program && cargo build-sbf

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN mkdir -p server challenge

COPY --from=builder /app/server/target/release/solchal-server server/
COPY --from=builder /app/program/target/deploy/solchal.so challenge/
COPY --from=builder /app/server/flag.txt server/

ARG PORT=5002
EXPOSE ${PORT}

WORKDIR /app/server
CMD ["./solchal-server"]
