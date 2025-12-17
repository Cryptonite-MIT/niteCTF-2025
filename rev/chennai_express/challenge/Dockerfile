FROM ubuntu:22.04

RUN useradd -m ctf
WORKDIR /home/ctf

COPY public/server ./server

# RUN echo "nite{T#r0ugh_g0e5_Th0m4s!!}" > flag.txt

RUN chown -R root:root /home/ctf && \
    chmod -R 555 /home/ctf

USER ctf

ENV FLAG="nite{T#r0ugh_g0e5_Th0m4s!!}"
ENV PORT=1337
EXPOSE $PORT 

ENTRYPOINT ["./server"]

