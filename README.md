# OxiProxy

A simple TCP/UDP connection redirector through socks5 with TLS inspection using a list of cloned CAs. 

Inspired by redproxy2

### Clone CAs
```bash
# Copy ROOT CA certs
cp /etc/ssl/certs/*.pem ./incerts/
# Clone CAs
cargo run -- clone-ca -i ./incerts -o ./outcerts --log-level 4
```

### Redirect traffic

Iptables redirect:

```bash
iptables -t nat -A OUTPUT --destination 127.0.0.1 -p tcp --dport 1081 -j REDIRECT --to-port 1080
iptables -t nat -A OUTPUT -p tcp --dport 1081 -j REDIRECT --to-port 1080
```

### Run server

```bash
cargo run -- proxy --port 1080 --root-ca ./outcerts/ --pinned-domain microsoft.com -l 5 --addr 127.0.0.1 --socks5-server 127.0.0.1:3128 --trace-folder ./traces
```

### Generated traces

All inspected traffic are stored in the traces folder with a metadata file about the connection and the raw or intercepted traffic sent and received.