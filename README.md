# phantomsocks
A cross-platform proxy client/server for Linux/Windows/macOS with Pcap/RawSocket/WinDivert
## Usage
```
./phantomsocks -h
Usage of ./phantomsocks:
  -log int
    	LogLevel
  -maxprocs int
    	MaxProcesses
  -install
    	Install service (Windows)
  -remove
    	Remove service (Windows)
  -start
    	Start service (Windows)
  -stop
    	Stop service (Windows)
```
## Configure
### config.json:
```
{
    "config": "1.conf,2.conf,3.conf",
    "socks": "address:port",
    "dns": "address:port",
    "redir": ":port",
    "vaddrprefix": 6,
    "proxy": "socks://address:port",
    "interfaces": [
        {
            "name": "default",
            "dns": "udp://8.8.8.8:53"
        },
        {
            "name": "https",
            "dns": "udp://8.8.8.8:53",
            "device": "eth0",
            "hint": "https"
        },
        {
            "name": "doh",
            "dns": "https://cloudflare-dns.com/dns-query"
        },
        {
            "name": "dot",
            "dns": "tls://8.8.8.8:853"
        },
        {
            "name": "ecs",
            "dns": "udp://8.8.8.8:53/?ecs=35.190.247.1"
        },
        {
            "name": "socks5",
            "protocol": "socks5",
            "address": "127.0.0.1:1080"
        },
        {
            "name": "socks4",
            "dns": "udp://8.8.8.8:53",
            "protocol": "socks4",
            "address": "127.0.0.1:1080"
        }
    ]
}
```
### Socks:
```
Linux:
edit config.json set socks as 127.0.0.1:1080
run phantomsocks

Windows(windivert):
edit config.json
    "socks": "127.0.0.1:1080",
    "proxy" :"socks://127.0.0.1:1080/?dns=127.0.0.1"
run phantomsocks

macOS:
edit config.json
    "socks": "127.0.0.1:1080",
    "proxy": "socks://127.0.0.1:1080"
run phantomsocks
```
### Redirect:
```
Linux:
iptables -t nat -A OUTPUT -d 6.0.0.0/8 -p tcp -j REDIRECT --to-port 6
edit config.json
    "redir": ":6",
    "vaddrprefix": 6
run phantomsocks

Windows(windivert):
edit config.json
    "redir": ":6",
    "vaddrprefix": 6,
    "proxy": "redirect://0.0.0.0:6"
run phantomsocks
```

### Rules
```
  [default]         #domains below will use the config of this interface
  domain=ip,ip,...  #this domain will use these IPs
  domain            #this domain will be resolved by DNS
  domain=[domain]   #this domain will use the config of this domain
  domain=domain     #this domain will use the addresses of this domain
  
  [dot]             #domains below will use the config of dot
  domain
  [socks5]          #domains below will use the config of socks5
  domain
```
## Installation
go get github.com/macronut/phantomsocks

## Compile
cd $GOPATH/src/github.com/macronut/phantomsocks/

go build

### pcap version
static linking for pcap
```
sudo apt-get install -y libpcap-dev
go build -tags pcap -ldflags '-extldflags "-static"'
```
### raw socket version
raw socket is Linux only
```
go build -tags rawsocket
```
### windivert version
windivert is Windows only
```
env GOOS=windows GOARCH=amd64 go build -tags windivert
```

### cross & static compile pcap version on Ubuntu 18.04
Install dependencies
```
apt-get install git autoconf automake bison build-essential flex gawk gettext gperf libtool pkg-config libpcap-dev
```
Download & uncompress tool-chain
```
cd ~/Downloads
wget https://downloads.openwrt.org/releases/19.07.2/targets/ramips/mt7621/openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64.tar.xz
tar -xJvf openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64.tar.xz
```
Set environment variable
```
export PATH=$PATH:~/Downloads/openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-7.5.0_musl/bin: && export STAGING_DIR=~/Downloads/openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-7.5.0_musl
```
Download & uncompress libpcap
```
wget https://www.tcpdump.org/release/libpcap-1.9.1.tar.gz
tar -xzvf libpcap-1.9.1.tar.gz
```
Build libpcap
```
cd libpcap-1.9.1
./configure --host=mipsel-openwrt-linux-musl --prefix='~/Downloads/openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-7.5.0_musl'
make && make install 
```
Build phantomsocks
```
cd ~/go/src/github.com/Macronut/phantomsocks
env GOOS=linux GOARCH=mipsle CGO_ENABLED=1 CC='~/Downloads/openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-7.5.0_musl/bin/mipsel-openwrt-linux-gcc'  go build  -ldflags '-extldflags "-static"'
```
