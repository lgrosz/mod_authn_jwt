FROM ubuntu:22.04 as builder

RUN apt-get update && apt-get install -y \
    cmake \
    libjwt-dev \
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


FROM ubuntu:22.04 as runner

RUN apt-get update && apt-get install -y \
    libjwt0 \
    && rm -rf /var/lib/apt/lists/*

# Install lighttpd
COPY --from=builder lighttpd-build/build/lighttpd /usr/local/bin
COPY --from=builder lighttpd-build/build/mod_*.so /usr/local/lib

# Import module
COPY --from=builder build/mod_authn_jwt.so /usr/local/lib

# Configure lighttpd
ADD lighttpd.conf /etc/lighttpd/lighttpd.conf
ADD conf.d /etc/lighttpd/conf.d

CMD lighttpd -D -f /etc/lighttpd/lighttpd.conf -m /usr/local/lib
