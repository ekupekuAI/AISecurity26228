# Hugging Face Spaces (Docker) image — a public, always-on demo mirror of TrustVision.
#
# It runs the Node gateway and the Python assurance engine in one container on port 7860
# (HF's port), with the read-only evaluation login enabled so judges can explore without
# an account. This is a demo mirror; the real deployment is the single air-gapped node.
#
# HF builds from the pushed git repo, which does not include the 45 MB backbone weight,
# so the `backbone` stage regenerates it from torchvision at build time (HF build has
# network). At runtime the engine never downloads weights.

# --- Python deps (CPU-only torch) -------------------------------------------------
FROM python:3.12-slim AS engine-deps
WORKDIR /build
COPY ml-engine/requirements.txt .
RUN pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu -r requirements.txt

# --- Reference backbone, staged at build time ------------------------------------
FROM engine-deps AS backbone
COPY ml-engine ./ml-engine
RUN python ml-engine/scripts/provision_backbone.py

# --- Frontend + gateway build -----------------------------------------------------
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

# --- Runtime ----------------------------------------------------------------------
FROM python:3.12-slim
LABEL org.opencontainers.image.title="TrustVision" \
      org.opencontainers.image.description="Air-gapped CV supply-chain assurance (SIH26228)"

RUN apt-get update \
 && apt-get install -y --no-install-recommends nodejs ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*

# HF Spaces run the container as uid 1000; make that user own the app.
RUN useradd --create-home --uid 1000 user

WORKDIR /app
COPY --from=engine-deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=engine-deps /usr/local/bin /usr/local/bin
COPY --from=console-build /build/node_modules ./node_modules
COPY --from=console-build /build/dist ./dist
COPY ml-engine ./ml-engine
COPY --from=backbone /build/ml-engine/assets/backbone_resnet18.pt ./ml-engine/assets/backbone_resnet18.pt
COPY deploy/entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh && mkdir -p /app/data && chown -R user:user /app

USER user
ENV HOME=/home/user \
    NODE_ENV=production \
    AIA_ENV=demo \
    AIA_DEMO_MODE=true \
    AIA_ALLOW_WEIGHT_DOWNLOAD=false \
    HOST=0.0.0.0 \
    PORT=7860 \
    ML_SERVICE_URL=http://127.0.0.1:8000 \
    AIA_TRUST_PROXY_HOPS=1 \
    PYTHONUNBUFFERED=1

EXPOSE 7860

# tini reaps the two child processes cleanly.
ENTRYPOINT ["/usr/bin/tini", "--", "/app/entrypoint.sh"]
