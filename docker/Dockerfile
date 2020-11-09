FROM alpine:latest AS builder

RUN   apk add --no-cache gcc libc-dev make upx

WORKDIR /src
COPY . /src

RUN    make \
    && make pidproxy.upx \
    && cp pidproxy.upx /

FROM scratch
COPY --from=builder /pidproxy.upx /pidproxy
