package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"

	ptcp "./phantomtcp"
	proxy "./proxy"
)

var allowlist map[string]bool = nil

func ListenAndServe(listenAddr string, serve func(net.Conn)) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panic(err)
	}

	if allowlist != nil {
		for {
			client, err := l.Accept()
			if err != nil {
				log.Panic(err)
			}
			err = proxy.SetKeepAlive(client)
			if err != nil {
				log.Panic(err)
			}

			remoteAddr := client.RemoteAddr()
			remoteTCPAddr, _ := net.ResolveTCPAddr(remoteAddr.Network(), remoteAddr.String())
			_, ok := allowlist[remoteTCPAddr.IP.String()]
			if ok {
				go serve(client)
			} else {
				client.Close()
			}
		}
	} else {
		for {
			client, err := l.Accept()
			if err != nil {
				log.Panic(err)
			}
			err = proxy.SetKeepAlive(client)
			if err != nil {
				log.Panic(err)
			}

			go serve(client)
		}
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

func DNSServer(listenAddr string) error {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	fmt.Println("DNS:", listenAddr)
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
				index, _ = ptcp.NSLookup(qname, 28, conf.Server)
			} else {
				index, _ = ptcp.NSLookup(qname, 1, conf.Server)
			}
			response := ptcp.BuildLie(data[:n], index, qtype)
			conn.WriteToUDP(response, clientAddr)
			continue
		}

		request := make([]byte, n)
		copy(request, data[:n])
		go func(clientAddr *net.UDPAddr, request []byte) {
			var response []byte
			var err error
			_server := strings.SplitN(ptcp.DNS, "/", 4)
			if len(_server) > 2 {
				switch _server[0] {
				case "udp:":
					if ptcp.LogLevel > 1 {
						fmt.Println("UDP:", clientAddr, qname)
					}
					response, err = ptcp.UDPlookup(request, _server[2])
				case "tcp:":
					if ptcp.LogLevel > 1 {
						fmt.Println("TCP:", clientAddr, qname)
					}
					response, err = ptcp.TCPlookup(request, _server[2])
				case "tls:":
					if ptcp.LogLevel > 1 {
						fmt.Println("DOT:", clientAddr, qname)
					}
					response, err = ptcp.TLSlookup(request, _server[2])
				default:
					return
				}
			}
			if err != nil {
				log.Println(err)
				return
			}
			conn.WriteToUDP(response, clientAddr)
		}(clientAddr, request)
	}
}

var configFiles = flag.String("c", "default.conf", "Config")
var hostsFile = flag.String("hosts", "", "Hosts")
var socksListenAddr = flag.String("socks", "", "Socks5")
var httpListenAddr = flag.String("http", "", "HTTP")
var pacListenAddr = flag.String("pac", "", "PACServer")
var sniListenAddr = flag.String("sni", "", "SNIProxy")
var redirectAddr = flag.String("redir", "", "Redirect")
var systemProxy = flag.String("proxy", "", "Proxy")
var dnsListenAddr = flag.String("dns", "", "DNS")
var device = flag.String("device", "", "Device")
var logLevel = flag.Int("log", 0, "LogLevel")
var clients = flag.String("clients", "", "Clients")

func main() {
	runtime.GOMAXPROCS(1)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.Parse()

	devices := strings.Split(*device, ",")
	if !ptcp.ConnectionMonitor(devices) {
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

	if *clients != "" {
		allowlist = make(map[string]bool)
		list := strings.Split(*clients, ",")
		for _, c := range list {
			allowlist[c] = true
		}
	}

	if *socksListenAddr != "" {
		fmt.Println("Socks:", *socksListenAddr)
		go ListenAndServe(*socksListenAddr, ptcp.SocksProxy)
		if *pacListenAddr != "" {
			go PACServer(*pacListenAddr, *socksListenAddr)
		}
	}

	if *httpListenAddr != "" {
		fmt.Println("HTTP:", *httpListenAddr)
		go ListenAndServe(*httpListenAddr, ptcp.HTTPProxy)
	}

	if *sniListenAddr != "" {
		fmt.Println("SNI:", *sniListenAddr)
		go ListenAndServe(*sniListenAddr, ptcp.SNIProxy)
	}

	if *redirectAddr != "" {
		fmt.Println("Redirect:", *redirectAddr)
		go ListenAndServe(*redirectAddr, ptcp.Proxy)
	}

	if *systemProxy != "" {
		for _, dev := range devices {
			err := proxy.SetProxy(dev, *systemProxy, true)
			if err != nil {
				fmt.Println(err)
			}
		}
	}

	if *dnsListenAddr != "" {
		go DNSServer(*dnsListenAddr)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	s := <-c
	fmt.Println(s)

	if *systemProxy != "" {
		for _, dev := range devices {
			err := proxy.SetProxy(dev, *systemProxy, false)
			if err != nil {
				fmt.Println(err)
			}
		}
	}
}
