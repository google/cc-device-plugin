FROM golang:1.26.2-trixie as build
WORKDIR /src
COPY . /src
RUN CGO_ENABLED=0 go build -o /cc-device-plugin

FROM debian:trixie-slim
LABEL maintainer="jimmychiu <jimmychiu@google.com>"

# Update and upgrade OS packages to patch vulnerabilities
RUN apt update && apt -y upgrade
RUN apt -y autoremove

COPY --from=build /cc-device-plugin /cc-device-plugin
ENTRYPOINT ["/cc-device-plugin"]
