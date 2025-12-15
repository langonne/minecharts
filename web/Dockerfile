FROM oven/bun:1 as builder

WORKDIR /app
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

ENV VITE_APP_VERSION=$VERSION \
    VITE_APP_COMMIT=$COMMIT \
    VITE_APP_BUILD_DATE=$BUILD_DATE

COPY package.json bun.lock* ./
COPY tsconfig.json uno.config.ts vite.config.ts ./
RUN bun install --frozen-lockfile

COPY src ./src

RUN bun run build

FROM nginx:1.25-alpine

RUN apk add --no-cache gettext openssl

ENV MINECHARTS_API_URL=http://localhost:30080 \
    ENABLE_TLS=true \
    SSL_CERT_PATH=/etc/nginx/certs/tls.crt \
    SSL_KEY_PATH=/etc/nginx/certs/tls.key

COPY --from=builder /app/dist /usr/share/nginx/html
COPY docker/nginx.conf.template /etc/nginx/templates/nginx.conf.template
COPY docker/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 80 443

ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
