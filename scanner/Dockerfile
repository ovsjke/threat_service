FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY contracts ./contracts
COPY scanner ./scanner
WORKDIR /src/scanner
RUN CGO_ENABLED=0 go build -trimpath -o /out/scanner ./cmd/scanner

FROM alpine:3.22
RUN adduser -D -u 10001 scanner
COPY --from=build /out/scanner /usr/local/bin/scanner
USER scanner
EXPOSE 8082
ENTRYPOINT ["/usr/local/bin/scanner"]
