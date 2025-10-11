FROM node:20-bullseye-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip ffmpeg ca-certificates && \
    pip3 install --no-cache-dir yt-dlp==2025.01.12 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json ./
RUN npm ci --omit=dev || npm i --omit=dev
COPY server.mjs ./

ENV NODE_ENV=production
# Apify sets ACTOR_WEB_SERVER_PORT at runtime. We EXPOSE 4321 for clarity.
EXPOSE 4321
CMD ["node", "server.mjs"]
