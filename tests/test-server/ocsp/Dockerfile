FROM alpine:3.19

RUN apk add --no-cache openssl bash

WORKDIR /ocsp

COPY start-ocsp.sh /ocsp/
RUN chmod +x /ocsp/start-ocsp.sh

EXPOSE 8888

CMD ["/ocsp/start-ocsp.sh"]
