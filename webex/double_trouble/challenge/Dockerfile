FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    apache2 \
    python3 \
    python3-pip \
    supervisor \
    wget \
    make \
    gcc \
    libssl-dev \
    libpcre3-dev \
    zlib1g-dev \
    openssl \
    && rm -rf /var/lib/apt/lists/*

RUN cd /tmp && \
    wget https://www.haproxy.org/download/2.0/src/haproxy-2.0.14.tar.gz && \
    tar xzf haproxy-2.0.14.tar.gz && \
    cd haproxy-2.0.14 && \
    make TARGET=linux-glibc USE_OPENSSL=1 USE_PCRE=1 USE_ZLIB=1 && \
    make install && \
    cd / && rm -rf /tmp/haproxy-2.0.14*

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
COPY app.py .

COPY httpd.conf /etc/apache2/httpd.conf

RUN mkdir -p /usr/local/etc/haproxy
COPY haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg

RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /usr/local/etc/haproxy/haproxy.pem \
    -out /usr/local/etc/haproxy/haproxy.pem \
    -days 365 \
    -subj "/C=US/ST=State/L=City/O=SecureAPI/CN=localhost"

RUN mkdir -p /run/haproxy && chmod 755 /run/haproxy

RUN mkdir -p /var/log/supervisor

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

ENV FLASK_ENV=production
ENV FLAG=nite{h11p_1_1_must_d1e}

EXPOSE 443 80 8404

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
