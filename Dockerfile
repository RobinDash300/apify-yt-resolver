# Use an official Node 20 slim image
FROM node:20-bullseye-slim

# Let the build control the yt-dlp version in a reproducible way
ARG YTDLP_VER=2025.01.12

# Install minimal runtime deps and fetch yt-dlp binary
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      ffmpeg \
      python3 \
    ; \
    update-ca-certificates; \
    curl -L "https://github.com/yt-dlp/yt-dlp/releases/download/${YTDLP_VER}/yt-dlp" \
      -o /usr/local/bin/yt-dlp; \
    chmod +x /usr/local/bin/yt-dlp; \
    # Clean up apt caches
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

# App directory
WORKDIR /app

# Copy and install only prod deps
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm i --omit=dev

# Copy server
COPY server.mjs ./

# Create a place for optional cookie files and make it readable
RUN mkdir -p /secrets && chmod 755 /secrets

# Environment for server.mjs
ENV NODE_ENV=production
# Where server.mjs expects yt-dlp
ENV YTDLP_PATH=/usr/local/bin/yt-dlp
# Optional: point this to a mounted Netscape cookies file for YouTube
# ENV YT_COOKIES_PATH=/secrets/youtube_cookies.txt
# Optional: pass extra yt-dlp args if needed
# ENV YTDLP_ARGS=--extractor-args tiktok:player_url=1
# Optional: route all traffic through a proxy
# ENV PROXY_URL=http://user:pass@host:port

# Apify sets ACTOR_WEB_SERVER_PORT at runtime. Expose 4321 for clarity.
EXPOSE 4321

# Basic container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD curl -fsS "http://127.0.0.1:${ACTOR_WEB_SERVER_PORT:-${PORT:-8080}}/_health" || exit 1

# Drop privileges
RUN useradd -m -u 10001 appuser && chown -R appuser:appuser /app /secrets
USER appuser

CMD ["node", "server.mjs"]
