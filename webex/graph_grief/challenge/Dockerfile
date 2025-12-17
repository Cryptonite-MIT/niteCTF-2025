FROM node:18-bullseye

RUN useradd -m ctf

WORKDIR /app

COPY package.json ./

RUN npm install --legacy-peer-deps

COPY . .

RUN chown -R ctf:ctf /app

ENV NODE_ENV=production

USER ctf

EXPOSE 8000

CMD export WOW_FLAG=$(cat flag.txt) && node server.js


