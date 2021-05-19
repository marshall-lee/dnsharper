# dnsharper

Small DNS server to lookup local network IPs by their MAC addresses.

## Build

`dnsharper` is written in Go so to build it you need `go` compiler.

```bash
% go build
```

## Run

To map IP to MAC address, `dnsharper` performs an ARP scan permanently. It means that it's required `root` privilege to run it.

You also might need to know which network interface you want to be scanned using `ifconfig`.

```bash
% ifconfig
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=400<CHANNEL_IO>
	inet 192.168.0.167 netmask 0xffffff00 broadcast 192.168.0.255
	nd6 options=201<PERFORMNUD,DAD>
	media: autoselect
	status: active
...
% sudo dnsharper en0
INFO[0010] Added IP 192.168.0.1 at ed-71-bd-20-aa-be.dnsharper.local
INFO[0010] Added IP 192.168.0.165 at 9f-1c-49-3b-22-f1.dnsharper.local
INFO[0010] Added IP 192.168.0.140 at 64-21-e7-96-ad-1f.dnsharper.local
INFO[0010] Added IP 192.168.0.182 at f1-9b-ad-a2-4e-d4.dnsharper.local
...
```

Suppose some machine in your local network is accessible at 192.168.0.1 and has the hardware address `ed:71:bd:20:aa:be`. Then it might be resolved from a `ed-71-bd-20-aa-be.dnsharper.local` domain name.

Lets open `nslookup` in a parallel terminal and test:

```bash
% nslookup
> server 127.0.0.1
> set port=5333
> ed-71-bd-20-aa-be.dnsharper.local
Server:		127.0.0.1
Address:	127.0.0.1#5333

Non-authoritative answer:
Name:	ed-71-bd-20-aa-be.dnsharper.local
Address: 192.168.0.1
```

For more options see `dnsharper --help`.

## Setup

### MacOS

You can integrate `dnsharper` to MacOS as a resolver. Create a file named `/etc/resolver/dnsharper`:

```
domain dnsharper.local
nameserver 127.0.0.1
port 5333
```

Test it:

```
% ping ed-71-bd-20-aa-be.dnsharper.local
PING ed-71-bd-20-aa-be.dnsharper.local (192.168.0.1): 56 data bytes
64 bytes from 192.168.0.1: icmp_seq=0 ttl=64 time=1.274 ms
64 bytes from 192.168.0.1: icmp_seq=1 ttl=64 time=1.265 ms
64 bytes from 192.168.0.1: icmp_seq=2 ttl=64 time=2.380 ms
```

### `dnsmasq`

Open `/etc/dnsmasq.conf` (or `/usr/local/etc/dnsmasq.conf` in MacOS) and add the line:

```
server=/.dnsharper.local/127.0.0.1#5333
```
