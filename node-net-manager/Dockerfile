FROM golang:alpine as builder

WORKDIR /app

# TODO ony copy needed files
COPY . .


RUN go mod tidy

RUN go build -o ./arm-7-NetManager ./NetManager.go


FROM alpine:latest

RUN mkdir -p /etc/netmanager

RUN apk --no-cache add iptables



WORKDIR /app

COPY --from=builder /app/arm-7-NetManager .
COPY --from=builder /app/config/netcfg.json /etc/netmanager/netcfg.json

USER root

CMD ["./arm-7-NetManager"]