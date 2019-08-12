FROM golang:1.12 as builder
LABEL maintainer="NIPE-SYSTEMS <dev.nipe.systems@gmail.com>"

WORKDIR /app

COPY . /app/

RUN CGO_ENABLED=0 GOOS=linux go build -o rfc2136-skydns-etcd-adaptor -v


FROM scratch

COPY --from=builder /app/rfc2136-skydns-etcd-adaptor .

ENTRYPOINT ["/rfc2136-skydns-etcd-adaptor"]
