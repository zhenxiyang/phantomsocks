package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"

	ptcp "github.com/macronut/phantomsocks/phantomtcp"
	proxy "github.com/macronut/phantomsocks/proxy"
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

		request := make([]byte, n)
		copy(request, data[:n])
		go func(clientAddr *net.UDPAddr, request []byte) {
			response := ptcp.NSRequest(request, true)
			conn.WriteToUDP(response, clientAddr)
		}(clientAddr, request)
	}
}

var StartFlags struct {
	ConfigFiles     string `json:"config,omitempty"`
	HostsFile       string `json:"hosts,omitempty"`
	SocksListenAddr string `json:"socks,omitempty"`
	PacListenAddr   string `json:"pac,omitempty"`
	SniListenAddr   string `json:"sni,omitempty"`
	RedirectAddr    string `json:"redir,omitempty"`
	SSListenAddr    string `json:"ss,omitempty"`
	SystemProxy     string `json:"proxy,omitempty"`
	DnsListenAddr   string `json:"dns,omitempty"`
	Device          string `json:"device,omitempty"`
	UDPDevice       string `json:"udpdev,omitempty"`
	Clients         string `json:"clients,omitempty"`
	LogLevel        int    `json:"log,omitempty"`
	MaxProcs        int    `json:"maxprocs,omitempty"`
}

func StartService() {
	if StartFlags.ConfigFiles == "" {
		conf, err := os.Open("phantomsocks.json")
		if err != nil {
			fmt.Println(err)
			return
		}

		bytes, err := ioutil.ReadAll(conf)
		if err != nil {
			log.Panic(err)
		}
		conf.Close()

		err = json.Unmarshal(bytes, &StartFlags)
		if err != nil {
			log.Panic(err)
		}

		if StartFlags.ConfigFiles == "" {
			StartFlags.ConfigFiles = "default.conf"
		}
	}

	if StartFlags.MaxProcs > 0 {
		runtime.GOMAXPROCS(StartFlags.MaxProcs)
	}

	if StartFlags.Device != "" {
		devices := strings.Split(StartFlags.Device, ",")
		if !ptcp.ConnectionMonitor(devices) {
			return
		}
	} else {
		ptcp.ConnectionMonitor("")
	}

	if StartFlags.UDPDevice != "" {
		udpdevices := strings.Split(StartFlags.UDPDevice, ",")
		if !ptcp.UDPMonitor(udpdevices) {
			return
		}
	}

	ptcp.LogLevel = StartFlags.LogLevel
	ptcp.Init()

	for _, filename := range strings.Split(StartFlags.ConfigFiles, ",") {
		err := ptcp.LoadConfig(filename)
		if err != nil {
			if ptcp.LogLevel > 0 {
				log.Println(err)
			}
			return
		}
	}
	if StartFlags.HostsFile != "" {
		err := ptcp.LoadHosts(StartFlags.HostsFile)
		if err != nil {
			if ptcp.LogLevel > 0 {
				log.Println(err)
			}
			return
		}
	}

	if StartFlags.Clients != "" {
		allowlist = make(map[string]bool)
		list := strings.Split(StartFlags.Clients, ",")
		for _, c := range list {
			allowlist[c] = true
		}
	}

	if StartFlags.SocksListenAddr != "" {
		fmt.Println("Socks:", StartFlags.SocksListenAddr)
		go ListenAndServe(StartFlags.SocksListenAddr, ptcp.SocksProxy)
		if StartFlags.PacListenAddr != "" {
			go PACServer(StartFlags.PacListenAddr, StartFlags.SocksListenAddr)
		}
	}

	if StartFlags.SniListenAddr != "" {
		fmt.Println("SNI:", StartFlags.SniListenAddr)
		go ListenAndServe(StartFlags.SniListenAddr, ptcp.SNIProxy)
	}

	if StartFlags.SSListenAddr != "" {
		addr := StartFlags.SSListenAddr
		if strings.HasPrefix(addr, "ss://") {
			accesskey := base64.StdEncoding.EncodeToString([]byte(addr[5:]))
			fmt.Println("ss://" + accesskey)
			ptcp.ShadowsocksServer(StartFlags.SSListenAddr)
		}
	}

	if StartFlags.RedirectAddr != "" {
		fmt.Println("Redirect:", StartFlags.RedirectAddr)
		go ListenAndServe(StartFlags.RedirectAddr, ptcp.RedirectProxy)
	}

	if StartFlags.SystemProxy != "" {
		for _, dev := range devices {
			err := proxy.SetProxy(dev, StartFlags.SystemProxy, true)
			if err != nil {
				fmt.Println(err)
			}
		}
	}

	if StartFlags.DnsListenAddr != "" {
		go DNSServer(StartFlags.DnsListenAddr)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	s := <-c
	fmt.Println(s)

	if StartFlags.SystemProxy != "" {
		for _, dev := range devices {
			err := proxy.SetProxy(dev, StartFlags.SystemProxy, false)
			if err != nil {
				fmt.Println(err)
			}
		}
	}
}

func main() {
	//log.SetFlags(log.LstdFlags | log.Lshortfile)

	var flagServiceInstall bool
	var flagServiceRemove bool
	var flagServiceStart bool
	var flagServiceStop bool

	if len(os.Args) > 1 {
		flag.StringVar(&StartFlags.ConfigFiles, "c", "default.conf", "Config")
		flag.StringVar(&StartFlags.HostsFile, "hosts", "", "Hosts")
		flag.StringVar(&StartFlags.SocksListenAddr, "socks", "", "Socks5")
		flag.StringVar(&StartFlags.PacListenAddr, "pac", "", "PACServer")
		flag.StringVar(&StartFlags.SniListenAddr, "sni", "", "SNIProxy")
		flag.StringVar(&StartFlags.SSListenAddr, "ss", "", "Shadowsocks")
		flag.StringVar(&StartFlags.RedirectAddr, "redir", "", "Redirect")
		flag.StringVar(&StartFlags.SystemProxy, "proxy", "", "Proxy")
		flag.StringVar(&StartFlags.DnsListenAddr, "dns", "", "DNS")
		flag.StringVar(&StartFlags.Device, "device", "", "Device")
		flag.StringVar(&StartFlags.UDPDevice, "udpdev", "", "UDP Device")
		flag.StringVar(&StartFlags.Clients, "clients", "", "Clients")
		flag.IntVar(&StartFlags.LogLevel, "log", 0, "LogLevel")
		flag.IntVar(&StartFlags.MaxProcs, "maxprocs", 0, "LogLevel")
		flag.BoolVar(&flagServiceInstall, "install", false, "Install service")
		flag.BoolVar(&flagServiceRemove, "remove", false, "Remove service")
		flag.BoolVar(&flagServiceStart, "start", false, "Start service")
		flag.BoolVar(&flagServiceStop, "stop", false, "Stop service")
		flag.Parse()

		if flagServiceInstall {
			proxy.InstallService()
			return
		}

		if flagServiceRemove {
			proxy.RemoveService()
			return
		}

		if flagServiceStart {
			proxy.StartService()
			return
		}

		if flagServiceStop {
			proxy.StopService()
			return
		}
	} else {
		if proxy.RunAsService(StartService) {
			return
		}
	}

	StartService()
}
