FROM golang:alpine as build


ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

WORKDIR /build
COPY . .

RUN mkdir /artifacts
RUN go build -o /artifacts/node-netmanager ./NetManager.go

FROM ubuntu:latest

ARG VERSION="0.0.1"

# LABEL io.k8s.display-name="Oakestra Node Network Plugin"
# LABEL name="Oakestra Node Network Plugin"
# LABEL vendor="Oakestra"
# LABEL version=${VERSION}
# LABEL summary="Oakestra Node Network Plugin for Kubernetes"
# LABEL description="See summary"

RUN echo $PATH

RUN mkdir -p /etc/netmanager

RUN echo "89" > /etc/netmanager/netcfg.json

COPY --from=build /artifacts/node-netmanager        /bin/node-netmanager

ENTRYPOINT ["node-netmanager"]




# FROM golang:alpine as builder

# WORKDIR /app

# # TODO ony copy needed files
# COPY . .


# RUN go mod tidy

# RUN go build -o ./arm-7-NetManager ./NetManager.go


# FROM alpine:latest

# RUN mkdir -p /etc/netmanager

# RUN apk --no-cache add iptables



# WORKDIR /app

# COPY --from=builder /app/arm-7-NetManager .
# COPY --from=builder /app/config/netcfg.json /etc/netmanager/netcfg.json

# USER root

# CMD ["./arm-7-NetManager"]