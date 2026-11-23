## Etapa de compilación
FROM golang:1.27-alpine AS builder

RUN apk add --no-cache ca-certificates

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# La imagen lleva el servicio y auditctl (para exportar y aplicar la retención
# judicial desde dentro de la red del stack). audit-keygen y audit-open NO van en
# la imagen: manejan la clave privada, que ningún servicio carga ni custodia.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/audit ./cmd/api \
 && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/auditctl ./cmd/auditctl

## Etapa final: imagen mínima sin shell ni herramientas adicionales
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /build/audit /audit
COPY --from=builder /build/auditctl /auditctl

# Usuario sin privilegios.
USER 65532:65532

EXPOSE 8080

ENTRYPOINT ["/audit"]
