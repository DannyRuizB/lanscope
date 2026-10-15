FROM node:24-alpine

# OCI image labels — show up on the GHCR package page and in `docker inspect`.
LABEL org.opencontainers.image.title="LanScope"
LABEL org.opencontainers.image.description="Visual LAN scanner — point it at a CIDR, see who's there. Web UI on top of nmap, results stored locally in SQLite."
LABEL org.opencontainers.image.source="https://github.com/DannyRuizB/lanscope"
LABEL org.opencontainers.image.url="https://github.com/DannyRuizB/lanscope"
LABEL org.opencontainers.image.documentation="https://github.com/DannyRuizB/lanscope#readme"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.authors="Danny Ruiz Boluda"

# nmap with raw socket capabilities; ip/iproute2 for default-gateway detection.
# su-exec drops from root to `node` in the entrypoint.
RUN apk add --no-cache nmap nmap-scripts libcap su-exec \
  && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

# nmap only trusts uid 0 unless told otherwise: with this set, the `node` user
# uses the file capabilities above for SYN/UDP scans, OS detection and the ARP
# ping that reports MAC addresses (measured: without it -sS and -O quit with
# "requires root privileges" and the sweep comes back with no MACs).
ENV NMAP_PRIVILEGED=""

WORKDIR /app

COPY package.json ./
# --ignore-scripts: better-sqlite3 >= 13 bundles a linuxmusl-x64 prebuild in
# the tarball, but npm's implicit `node-gyp rebuild` still wants python3/make
# even when there is nothing to compile — skipping scripts keeps the image
# free of build tools. No other dependency has an install script.
RUN npm install --omit=dev --ignore-scripts

COPY src/ ./src/

# Both data locations (the compose file's DB_PATH and the default one) are
# born owned by `node`, so a fresh named volume starts out writable.
RUN mkdir -p /var/lib/lanscope /app/data \
  && chown node:node /var/lib/lanscope /app/data

COPY docker-entrypoint.sh /usr/local/bin/lanscope-entrypoint

ENV NODE_ENV=production
ENV PORT=3030

EXPOSE 3030

# v1.54.0 — the server and its nmap run as `node`, not root (the entrypoint
# takes over a root-owned volume from older versions, then drops privileges).
ENTRYPOINT ["lanscope-entrypoint"]
CMD ["node", "src/server.js"]
