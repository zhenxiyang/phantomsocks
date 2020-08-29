# phantomsocks
A proxy server for Windows/Linux/macOS with WinPcap/LibPcap/RawSocket/WinDivert to modify packets
## Usage
```
phantomsocks
  -c string
    	Config (default "default.conf")
  -device string
    	Device
  -dns string
    	DNS
  -hosts string
    	Hosts
  -log int
    	LogLevel
  -pac string
    	PACServer
  -sni string
    	SNIProxy
  -socks string 
    	Socks5
```
## Configure
```
  server=IP:Port    #Domain in config will use this DNS(DNSoverTCP),if not set it will use the DNS of system
  ipv6=true/false   #Domain below will enable/disable IPv6 
  ttl=*             #the fake tcp packet will use this TTL
  domain=ip,ip,...  #this domain will use these IPs
  domain            #this domain will be resolved by DNS
  ip:port           #this ip:port will send fake packet when creating connection
  method=*          #the methods to modify TCP
  ```
### methods:
```
  ttl               #the fake tcp packets will use the TTL you set
  w-md5             #the fake tcp packets will have a wrong md5 option
  w-csum            #the fake tcp packets will have a wrong checksum
  w-ack             #the fake tcp packets will have a wrong ACK number
  tfo               #SYN packet will take a part of data when the server supports TCP Fast Open
  https             #the domain below will be move to https when using http on port 80
```
## Installation
### pcap version
```
go build phantomsocks.go
```
static linking 
```
go build -ldflags '-extldflags "-static"' phantomsocks.go
```
### raw socket version
raw socket is used by default on Linux/mipsle, you can edit pcap.go & raw.go to use this version on all Linux
```
env GOOS=linux GOARCH=mipsle go build phantomsocks.go
```
### cross & static compile on Ubuntu 18.04
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
env GOOS=linux GOARCH=mipsle CGO_ENABLED=1 CC='~/Downloads/openwrt-sdk-19.07.2-ramips-mt7621_gcc-7.5.0_musl.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-7.5.0_musl/bin/mipsel-openwrt-linux-gcc'  go build  -ldflags '-extldflags "-static"'  phantomsocks.go
```
