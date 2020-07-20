package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"runtime"
	"strings"

	ptcp "./phantomtcp"
)

func SocksProxy(listenAddr string) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("Socks:", listenAddr)
	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}

		go ptcp.SocksProxy(client)
	}
}

func SNIProxy(listenAddr string) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("SNIProxy:", listenAddr)
	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}

		go ptcp.SNIProxy(client)
	}
}

func Proxy(listenAddr string) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("Proxy:", listenAddr)
	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}

		go ptcp.Proxy(client)
	}
}

func PACServer(listenAddr string, proxyAddr string) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panic(err)
	}
	pac := ptcp.GetPAC(proxyAddr)
	response := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length:%d\r\n\r\n%s", len(pac), pac))
	fmt.Println("PACServer:", listenAddr)
	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}

		go func() {
			defer client.Close()
			var b [1024]byte
			_, err := client.Read(b[:])
			if err != nil {
				return
			}
			_, err = client.Write(response)
			if err != nil {
				return
			}
		}()
	}
}

func DNSServer(listenAddr, defaultDNS string) error {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	fmt.Println("DNS:", defaultDNS, listenAddr)
	data := make([]byte, 512)
	for {
		n, clientAddr, err := conn.ReadFromUDP(data)
		if err != nil {
			continue
		}
		qname, qtype, _ := ptcp.GetQName(data[:n])
		conf, ok := ptcp.ConfigLookup(qname)
		if ok {
			index := 0
			if conf.Option&ptcp.OPT_IPV6 != 0 {
				index, _ = ptcp.NSLookup(qname, 28)
			} else {
				index, _ = ptcp.NSLookup(qname, 1)
			}
			response := ptcp.BuildLie(data[:n], index, qtype)
			conn.WriteToUDP(response, clientAddr)
			continue
		}

		if defaultDNS != "" {
			if ptcp.LogLevel > 1 {
				fmt.Println("DNS:", clientAddr, qname)
			}
			dnsConn, err := net.Dial("udp", defaultDNS)
			if err != nil {
				log.Println(err)
				continue
			}
			_, err = dnsConn.Write(data[:n])
			if err != nil {
				log.Println(err)
				dnsConn.Close()
				continue
			}
			go func(clientAddr *net.UDPAddr, dnsConn net.Conn) {
				defer dnsConn.Close()
				recv := make([]byte, 1480)
				n, err := dnsConn.Read(recv)
				if err != nil {
					log.Println(err)
					return
				}
				conn.WriteToUDP(recv[:n], clientAddr)
			}(clientAddr, dnsConn)
		} else {
			if ptcp.LogLevel > 1 {
				fmt.Println("DoT:", clientAddr, qname)
			}

			response := make([]byte, n)
			copy(response, data[:n])
			go func(clientAddr *net.UDPAddr, response []byte) {
				recv, err := ptcp.TLSlookup(response, ptcp.DNS)
				if err != nil {
					log.Println(err)
					return
				}
				conn.WriteToUDP(recv[:n], clientAddr)
			}(clientAddr, response)
		}
	}
	return nil
}

var configFiles = flag.String("c", "default.conf", "Config")
var hostsFile = flag.String("hosts", "", "Hosts")
var socksListenAddr = flag.String("socks", "", "Socks5")
var pacListenAddr = flag.String("pac", "", "PACServer")
var sniListenAddr = flag.String("sni", "", "SNIProxy")
var proxyListenAddr = flag.String("proxy", "", "Proxy")
var dnsListenAddr = flag.String("dns", "", "DNS")
var device = flag.String("device", "", "Device")
var logLevel = flag.Int("log", 0, "LogLevel")

func main() {
	runtime.GOMAXPROCS(1)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.Parse()

	if *device == "" {
		ptcp.DevicePrint()
		return
	}

	ptcp.LogLevel = *logLevel
	ptcp.Init()
	for _, filename := range strings.Split(*configFiles, ",") {
		err := ptcp.LoadConfig(filename)
		if err != nil {
			if ptcp.LogLevel > 0 {
				log.Println(err)
			}
			return
		}
	}
	if *hostsFile != "" {
		err := ptcp.LoadHosts(*hostsFile)
		if err != nil {
			if ptcp.LogLevel > 0 {
				log.Println(err)
			}
			return
		}
	}

	if *socksListenAddr != "" {
		go SocksProxy(*socksListenAddr)
		if *pacListenAddr != "" {
			go PACServer(*pacListenAddr, *socksListenAddr)
		}
	}

	if *sniListenAddr != "" {
		go SNIProxy(*sniListenAddr)
	}

	if *proxyListenAddr != "" {
		go Proxy(*proxyListenAddr)
	}

	if *dnsListenAddr != "" {
		go DNSServer(*dnsListenAddr, "")
	}

	devices := strings.Split(*device, ",")
	ptcp.ConnectionMonitor(devices)
}
