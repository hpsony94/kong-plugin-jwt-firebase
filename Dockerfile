FROM abaez/luarocks
MAINTAINER [Sony Huynh](hpsony94@gmail.com)

RUN apk --update add zip

WORKDIR /home/app
COPY . .
