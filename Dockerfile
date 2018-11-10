FROM alpine:3.7
COPY Dockerfile /etc/Dockerfile
COPY tinyweb /bin/tinyweb
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN chmod +x /bin/tinyweb
ENTRYPOINT ["/entrypoint.sh"]

# docker build . -t cyd01/tinyweb

# docker run -d --rm --name tinyweb -e "TINYWEB_PORT=9909" -p 80:9909 -v $(pwd):/www cyd01/tinyweb
