# Single-image build for an air-gapped assurance node.
#
# Both processes run in one container because the gateway->engine hop is loopback by
# design: keeping them in separate containers would put that hop on a network the
# threat model assumes is hostile.
#
# Build on a connected machine, export with `docker save`, load on the node.

FROM python:3.12-slim AS engine-deps
WORKDIR /build
COPY ml-engine/requirements.txt .
# CPU-only torch: the GPU wheels are ~2 GB and nothing here needs CUDA.
RUN pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu -r requirements.txt

FROM node:22-slim AS console-build
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json vite.config.ts index.html ./
COPY public ./public
COPY src ./src
COPY server ./server
COPY server.ts ./
RUN npm run build && npm prune --omit=dev

FROM python:3.12-slim
LABEL org.opencontainers.image.title="AI Integrity Assurance Platform" \
      org.opencontainers.image.description="Air-gapped CV supply-chain assurance (SIH26228)"

# Node runtime alongside Python; no build toolchain in the final image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nodejs ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*

# Unprivileged: nothing here needs root, and the data directory is the only writable path.
RUN useradd --system --create-home --uid 10001 assurance

WORKDIR /app
COPY --from=engine-deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=console-build /build/node_modules ./node_modules
COPY --from=console-build /build/dist ./dist
COPY ml-engine ./ml-engine
COPY deploy/entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh && mkdir -p /app/data && chown -R assurance:assurance /app

USER assurance
ENV NODE_ENV=production \
    AIA_ENV=production \
    AIA_DEMO_MODE=false \
    AIA_ALLOW_WEIGHT_DOWNLOAD=false \
    HOST=0.0.0.0 \
    PORT=3000 \
    ML_SERVICE_URL=http://127.0.0.1:8000 \
    PYTHONUNBUFFERED=1

VOLUME ["/app/data"]
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# tini reaps the two child processes so a stopped container does not leave zombies.
ENTRYPOINT ["/usr/bin/tini", "--", "/app/entrypoint.sh"]
