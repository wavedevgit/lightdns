FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/lightdns ./cmd/lightdns && mkdir /out/state

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/lightdns /lightdns
COPY --from=build --chown=65532:65532 /out/state /var/lib/lightdns
USER 65532:65532
EXPOSE 53/udp 53/tcp 8080/tcp
ENTRYPOINT ["/lightdns"]
