# BerOps sunucu imajı: konsol (React) + berops-server (Go), PostgreSQL ayrı konteynerde.
#   docker build -f deploy/Dockerfile -t berops-server .

FROM node:24-alpine AS console
WORKDIR /src/console
COPY console/package.json console/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY console/ ./
COPY design/ /src/design/
RUN npm run build

FROM golang:1.27-alpine AS server
ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY shared/ shared/
COPY server/ server/
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/BerkayAtag/BerOps/shared/version.Version=${VERSION} -X github.com/BerkayAtag/BerOps/shared/version.Commit=${COMMIT}" \
    -o /out/berops-server ./server/cmd/berops-server

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S ber && adduser -S -G ber -h /var/lib/ber ber
COPY --from=server /out/berops-server /usr/local/bin/berops-server
COPY --from=console /src/console/dist /usr/share/ber/console
ENV BER_DATA_DIR=/var/lib/ber \
    BER_CONSOLE_STATIC_DIR=/usr/share/ber/console
USER ber
WORKDIR /var/lib/ber
VOLUME ["/var/lib/ber"]
EXPOSE 8443 52311
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD wget -q --no-check-certificate -O /dev/null https://127.0.0.1:8443/api/v1/health || exit 1
ENTRYPOINT ["berops-server"]
CMD ["serve"]
