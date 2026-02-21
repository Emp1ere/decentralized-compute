FROM golang:1.21-alpine AS build
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -o sidecar .

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=build /app/sidecar /sidecar
EXPOSE 7051
ENTRYPOINT ["/sidecar"]
