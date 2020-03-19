WS to TCP proxy

Simple daemon to proxify WebSocket connections to TCP

WebSocket client connects to the uri:

ws://**proxy_host**:**proxy_port**?host=**tcp_dst_host**&port=**tcp_dst_port**

to be proxified to the **tcp_dst_host**:**tcp_dst_port** TCP destination

## Building from sources (Debian)

### install dependencies
```sh
# apt install git cmake devscripts build-essential
```

### get sources
```sh
$ git clone https://github.com/furmur/virtualizm-websockify.git
$ cd virtualizm-websockify
```

### build deb package
```sh
$ debuild -us -uc -b
```

[Yeti]:https://yeti-switch.org/
[Documentation]:https://yeti-switch.org/docs/en/
