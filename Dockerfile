FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    bzip2 \
    cmake \
    libjansson-dev \
    libpcre2-dev \
    libssl-dev \
    ninja-build \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Download and build libjwt
ADD https://github.com/benmcollins/libjwt/releases/download/v3.1.0/libjwt-3.1.0.tar.xz libjwt-3.1.0.tar.xz
RUN tar -xJf libjwt-3.1.0.tar.xz
RUN cmake -S libjwt-3.1.0 -B libjwt-build
RUN cmake --build libjwt-build --target install

# Download lighttpd
ADD https://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-1.4.75.tar.gz lighttpd-1.4.75.tar.gz
RUN tar -xzf lighttpd-1.4.75.tar.gz

# Patch lighttpd
COPY . src
RUN cp src/mod_authn_jwt.c /lighttpd-1.4.75/src
RUN cp src/CMakeLists.txt.patch /lighttpd-1.4.75
RUN \
    cd /lighttpd-1.4.75 && \
    patch -p1 <CMakeLists.txt.patch

# Build lighttpd
RUN cmake -S lighttpd-1.4.75 -B lighttpd-build -DWITH_JWT=ON
RUN cmake --build lighttpd-build

FROM builder AS tester

RUN ctest --build lighttpd-build

FROM ubuntu:22.04 AS runner

RUN apt-get update && apt-get install -y \
    curl \
    libjansson4 \
    && rm -rf /var/lib/apt/lists/*

# Install libjwt
COPY --from=builder /usr/local/lib/libjwt.so* /usr/lib

# Install lighttpd
COPY --from=builder lighttpd-build/build/lighttpd /usr/local/bin

# Install modules
RUN install -d /usr/local/lib/lighttpd
COPY --from=builder lighttpd-build/build/mod_*.so /usr/local/lib/lighttpd

# Configure lighttpd
ADD lighttpd.conf /etc/lighttpd/lighttpd.conf
ADD conf.d /etc/lighttpd/conf.d

CMD lighttpd -D -f /etc/lighttpd/lighttpd.conf
