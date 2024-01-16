FROM golang:1.21 as build
WORKDIR /src
COPY . /src
RUN CGO_ENABLED=0 go build -o /cc-device-plugin

FROM debian:trixie-slim
LABEL maintainer="ruidezhang <ruidezhang@google.com>"
COPY --from=build /cc-device-plugin /cc-device-plugin
ENTRYPOINT ["/cc-device-plugin"]
