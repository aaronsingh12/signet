# One build, one image per service (BP 2 principle 6). Targets: control, gateway.
#   docker build --target control -t signet/control .
#   docker build --target gateway -t signet/gateway .
# CI signs both images with cosign (keyless) and publishes a CycloneDX SBOM (.github/workflows/ci.yml).

FROM node:24-slim AS build
WORKDIR /src
COPY package.json package-lock.json ./
COPY packages ./packages
COPY apps ./apps
COPY scripts ./scripts
COPY policy ./policy
RUN npm ci --ignore-scripts && npm run build

FROM node:24-slim AS runtime-base
ENV NODE_ENV=production SIGNET_HOME=/app SIGNET_DATA_DIR=/data
WORKDIR /app
RUN mkdir -p /data && chown node:node /data /app
COPY --from=build --chown=node:node /src/dist/policy ./policy
USER node
VOLUME ["/data"]

FROM runtime-base AS control
RUN npm init -y >/dev/null && npm install --omit=dev --ignore-scripts express@4.21.2 && npm cache clean --force
COPY --from=build /src/dist/control.mjs /src/dist/signet-verify.mjs ./
EXPOSE 4100
HEALTHCHECK CMD node -e "fetch('http://localhost:4100/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "control.mjs"]

FROM runtime-base AS gateway
RUN npm init -y >/dev/null && npm install --omit=dev express@4.21.2 @open-policy-agent/opa-wasm@1.10.0 @huggingface/transformers@3.7.6 && npm cache clean --force
COPY --from=build /src/dist/gateway.mjs /src/dist/detector-worker.mjs ./
# Detector model files are mounted at /app/models (licence-reviewed, pinned by hash; DA 3).
EXPOSE 8100
HEALTHCHECK CMD node -e "fetch('http://localhost:8100/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "gateway.mjs"]
