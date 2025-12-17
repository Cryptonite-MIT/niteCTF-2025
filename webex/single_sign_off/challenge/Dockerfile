FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

ARG NITE_USER=qwertyuiop
ARG NITE_PASSWORD=SgYJBS9C1b1ohbazlE

RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    libssl-dev \
    python3 \
    python3-pip \
    nginx \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN wget https://curl.se/download/curl-7.80.0.tar.gz && \
    tar -xzf curl-7.80.0.tar.gz && \
    cd curl-7.80.0 && \
    ./configure --with-ssl --prefix=/usr/local && \
    make && \
    make install && \
    ldconfig && \
    cd .. && \
    rm -rf curl-7.80.0*

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY document-portal /app/document-portal
WORKDIR /app/document-portal
RUN gcc -o fetcher fetcher.c -L/usr/local/lib -lcurl -O2

RUN echo 'machine gitlab.internal.corp' > /root/.netrc && \
    echo '  login devuser' >> /root/.netrc && \
    echo '  password DevPass2024!' >> /root/.netrc && \
    echo '' >> /root/.netrc && \
    echo 'machine nite-sso' >> /root/.netrc && \
    echo "  login ${NITE_USER}" >> /root/.netrc && \
    echo "  password ${NITE_PASSWORD}" >> /root/.netrc && \
    echo '' >> /root/.netrc && \
    echo 'machine jenkins.internal.corp' >> /root/.netrc && \
    echo '  login jenkins-bot' >> /root/.netrc && \
    echo '  password AutomationKey789' >> /root/.netrc && \
    echo 'default' >> /root/.netrc && \
    chmod 600 /root/.netrc

WORKDIR /app
COPY nite-vault /app/nite-vault

COPY nite-sso /app/nite-sso

COPY nginx.conf /etc/nginx/nginx.conf
COPY supervisord.conf /app/supervisord.conf
COPY init.sh /app/init.sh
COPY start.sh /app/start.sh

RUN mkdir -p /var/log/nginx /var/lib/nginx /var/cache/nginx /run/nginx && \
    chmod +x /app/init.sh /app/start.sh

ENV DOMAIN=single-sign-off.chals.nitephase.live
ENV DOCUMENT_PORTAL_PORT=10000
ENV NITE_VAULT_PORT=5000
ENV NITE_SSO_PORT=8989
ENV NITE_USER=qwertyuiop
ENV NITE_PASSWORD=SgYJBS9C1b1ohbazlE
ENV FLAG=nite{fake_flag}
ENV COMPANY_NAME=nite
ENV SECRET_KEY=lol-secret-key-lol

ENV SSO_EXTERNAL_URL=http://nite-sso.${DOMAIN}
ENV PORTAL_EXTERNAL_URL=http://document-portal.${DOMAIN}

EXPOSE 80

CMD ["bash", "/app/init.sh"]
