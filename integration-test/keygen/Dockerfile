FROM alpine:latest
RUN apk --no-cache add openssl
COPY generate-keys.sh /generate-keys.sh
RUN chmod +x /generate-keys.sh
RUN mkdir /private /public
CMD ["/generate-keys.sh"]
