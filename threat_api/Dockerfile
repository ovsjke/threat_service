
FROM golang:1.27.1-alpine AS build

WORKDIR /src
COPY contracts ./contracts
COPY threat_api ./threat_api

WORKDIR /src/threat_api

RUN go mod edit \
    -replace=github.com/ovsjke/threat_service/contracts=../contracts

RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -o /out/app ./cmd/app

FROM alpine:3.22

RUN adduser -D -u 10001 app
WORKDIR /app

COPY --from=build /out/app /app/app

USER app
EXPOSE 8080 50051

CMD ["/app/app"]
