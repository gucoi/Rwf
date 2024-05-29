# Rwf

Rwf is an opengfw written in rust that support that supports protection against some protocols, but it‘s not yet complete
## How to Build Locally?

```bash
cargo build
```

## How to Test Locally?

```bash
cargo test
```

## Features
* Full IP/TCP reassembly, various protocol analyzers
* HTTP, TLS, QUIC, DNS, SSH, SOCKS4/5, WireGuard, OpenVPN, and many more to come
* "Fully encrypted traffic" detection for Shadowsocks, VMess, etc. (https://gfw.report/publications/usenixsecurity23/en/) //TODO
* Trojan (proxy protocol) detection //TODO
* [WIP] Machine learning based traffic classification //TODO
