FROM golang:1.12 as builder
LABEL maintainer="NIPE-SYSTEMS <dev.nipe.systems@gmail.com>"

WORKDIR /app

COPY . /app/

RUN go build -o coredns-rfc2136-updater -v


FROM scratch

COPY --from=builder /app/coredns-rfc2136-updater .

ENTRYPOINT ["/coredns-rfc2136-updater"]
