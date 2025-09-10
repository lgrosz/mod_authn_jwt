FROM alpine:latest
RUN apk --no-cache add \
  bash \
  cmake \
  gcc \
  jansson-dev \
  libc-dev \
  make \
  openssl \
  openssl-dev \
  pkgconfig

ADD https://github.com/benmcollins/libjwt/releases/download/v3.2.2/libjwt-3.2.2.tar.xz libjwt-3.2.2.tar.xz
RUN tar -xJf libjwt-3.2.2.tar.xz
RUN cmake -S libjwt-3.2.2 -B libjwt-build
RUN cmake --build libjwt-build --target install

COPY generate-keys.sh /generate-keys.sh
RUN chmod +x /generate-keys.sh
RUN mkdir /private /public
CMD ["/generate-keys.sh"]
