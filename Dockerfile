FROM node:20-alpine

# nmap with raw socket capabilities; ip/iproute2 for default-gateway detection
RUN apk add --no-cache nmap nmap-scripts libcap \
  && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY src/ ./src/

ENV NODE_ENV=production
ENV PORT=3030

EXPOSE 3030

CMD ["node", "src/server.js"]
