FROM    ubuntu as builder

ARG     DEBIAN_FRONTEND=noninteractive
RUN     apt-get update && apt-get install --yes build-essential file gcc-multilib
COPY    Dockerfile /etc/Dockerfile
RUN     touch /etc/Dockerfile

COPY    src/tinyweb.c /tmp/tinyweb.c
RUN     gcc -m32 --static -o /usr/local/bin/tinyweb /tmp/tinyweb.c && /usr/local/bin/tinyweb -h

FROM    alpine
COPY    --from=builder /usr/local/bin/tinyweb /usr/local/bin/tinyweb
RUN     chmod +x /usr/local/bin/tinyweb ; /usr/local/bin/tinyweb -h

COPY    entrypoint.sh /entrypoint.sh
RUN     chmod +x /entrypoint.sh
RUN     echo '<html><head><title>It works!</title></head><body>It works!</body></html>' > /www/index.html

EXPOSE  80
WORKDIR /www

ENTRYPOINT [ "/entrypoint.sh" ]
