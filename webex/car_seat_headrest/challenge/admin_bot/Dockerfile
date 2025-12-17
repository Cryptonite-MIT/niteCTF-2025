FROM node:18-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libxshmfence1 \
    libxfixes3 \
    libxext6 \
    libx11-6 \
    libxcb1 \
    libpango-1.0-0 \
    libcairo2 \
    && rm -rf /var/lib/apt/lists/*


RUN apt-get update && \
    apt-get install -y ca-certificates && \
    update-ca-certificates && \
    curl -L -o chrome-linux.zip \
    "https://storage.googleapis.com/chromium-browser-snapshots/Linux_x64/1441427/chrome-linux.zip" && \
    unzip -q chrome-linux.zip && \
    rm chrome-linux.zip && \
    chmod +x chrome-linux/chrome


COPY package*.json ./
RUN npm install --production

COPY bot.js server.js ./

EXPOSE 4000



CMD ["node", "server.js"]
