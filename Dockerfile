FROM ubuntu:22.04 as builder

RUN apt-get update && apt-get install -y \
    cmake \
    libpcre2-dev \
    && rm -rf /var/lib/apt/lists/*

# Download and build lighttpd
ADD https://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-1.4.75.tar.gz lighttpd-1.4.75.tar.gz
RUN tar -xzf lighttpd-1.4.75.tar.gz
RUN cmake -S lighttpd-1.4.75 -B lighttpd-build
RUN cmake --build lighttpd-build

# Build project
COPY . src
RUN cmake -S src -B build -DLIGHTTPD_SOURCE_DIR=/lighttpd-1.4.75 -DLIGHTTPD_BUILD_DIR=/lighttpd-build
RUN cmake --build build
