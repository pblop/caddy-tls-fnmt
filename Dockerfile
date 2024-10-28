FROM docker.io/library/golang:1.23.2
WORKDIR /opt/caddy
COPY . .
RUN apt-get update && apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
RUN curl -1sLf 'https://dl.cloudsmith.io/public/caddy/xcaddy/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-xcaddy-archive-keyring.gpg \
  && curl -1sLf 'https://dl.cloudsmith.io/public/caddy/xcaddy/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-xcaddy.list \
  && apt-get update && apt-get install -y xcaddy

RUN apt-get install -y libnss3-tools

CMD xcaddy run
