package phantomtcp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

type PhantomServer struct {
	Option uint32
	TTL    byte
	MAXTTL byte
	MSS    uint16
	Server string
	Device string
}

var DomainMap map[string]*PhantomServer
var DefaultServer *PhantomServer = nil

var SubdomainDepth = 2
var LogLevel = 0
var Forward bool = false

const (
	OPT_NONE = 0x0

	OPT_TTL   = 0x1 << 0
	OPT_MSS   = 0x1 << 1
	OPT_WMD5  = 0x1 << 2
	OPT_NACK  = 0x1 << 3
	OPT_WACK  = 0x1 << 4
	OPT_WCSUM = 0x1 << 5
	OPT_WSEQ  = 0x1 << 6
	OPT_WTIME = 0x1 << 7

	OPT_TFO   = 0x1 << 8
	OPT_UDP   = 0x1 << 9
	OPT_HTTP3 = 0x1 << 10
	OPT_NOTCP = 0x1 << 11

	OPT_MODE2     = 0x1 << 12
	OPT_DF        = 0x1 << 13
	OPT_SAT       = 0x1 << 14
	OPT_RAND      = 0x1 << 15
	OPT_SSEG      = 0x1 << 16
	OPT_1SEG      = 0x1 << 17
	OPT_HTFO      = 0x1 << 18
	OPT_KEEPALIVE = 0x1 << 19
	OPT_SYNX2     = 0x1 << 20
	OPT_ZERO      = 0x1 << 21

	OPT_HTTP     = 0x1 << 23
	OPT_HTTPS    = 0x1 << 24
	OPT_MOVE     = 0x1 << 25
	OPT_STRIP    = 0x1 << 26
	OPT_FRONTING = 0x1 << 27
	OPT_IPV4     = 0x1 << 28
	OPT_IPV6     = 0x1 << 29
	OPT_PROXY    = 0x1 << 30
)

const OPT_FAKE = OPT_TTL | OPT_WMD5 | OPT_NACK | OPT_WACK | OPT_WCSUM | OPT_WSEQ | OPT_WTIME
const OPT_MODIFY = OPT_FAKE | OPT_SSEG | OPT_TFO | OPT_HTFO | OPT_MODE2

var MethodMap = map[string]uint32{
	"none":   OPT_NONE,
	"ttl":    OPT_TTL,
	"mss":    OPT_MSS,
	"w-md5":  OPT_WMD5,
	"n-ack":  OPT_NACK,
	"w-ack":  OPT_WACK,
	"w-csum": OPT_WCSUM,
	"w-seq":  OPT_WSEQ,
	"w-time": OPT_WTIME,

	"tfo":    OPT_TFO,
	"udp":    OPT_UDP,
	"h3":     OPT_HTTP3,
	"no-tcp": OPT_NOTCP,

	"mode2":      OPT_MODE2,
	"df":         OPT_DF,
	"sat":        OPT_SAT,
	"rand":       OPT_RAND,
	"s-seg":      OPT_SSEG,
	"1-seg":      OPT_1SEG,
	"half-tfo":   OPT_HTFO,
	"keep-alive": OPT_KEEPALIVE,
	"synx2":      OPT_SYNX2,
	"zero":       OPT_ZERO,

	"http":     OPT_HTTP,
	"https":    OPT_HTTPS,
	"move":     OPT_MOVE,
	"strip":    OPT_STRIP,
	"fronting": OPT_FRONTING,
	"ipv4":     OPT_IPV4,
	"ipv6":     OPT_IPV6,
	"proxy":    OPT_PROXY,
}

var Logger *log.Logger

func logPrintln(level int, v ...interface{}) {
	if LogLevel >= level {
		fmt.Println(v...)
	}
}

func ConfigLookup(name string) *PhantomServer {
	config, ok := DomainMap[name]
	if ok {
		return config
	}

	offset := 0
	for i := 0; i < SubdomainDepth; i++ {
		off := strings.Index(name[offset:], ".")
		if off == -1 {
			break
		}
		offset += off
		config, ok = DomainMap[name[offset:]]
		if ok {
			return config
		}
		offset++
	}

	return DefaultServer
}

func GetConfig(name string) *PhantomServer {
	config, ok := DomainMap[name]
	if ok {
		return config
	}

	return DefaultServer
}

func GetHost(b []byte) (offset int, length int) {
	offset = bytes.Index(b, []byte("Host: "))
	if offset == -1 {
		return 0, 0
	}
	offset += 6
	length = bytes.Index(b[offset:], []byte("\r\n"))
	if length == -1 {
		return 0, 0
	}

	return
}

func GetSNI(b []byte) (offset int, length int) {
	offset = 11 + 32
	if offset+1 > len(b) {
		return 0, 0
	}
	if b[0] != 0x16 {
		return 0, 0
	}
	Version := binary.BigEndian.Uint16(b[1:3])
	if (Version & 0xFFF8) != 0x0300 {
		return 0, 0
	}
	Length := binary.BigEndian.Uint16(b[3:5])
	if len(b) <= int(Length)-5 {
		return 0, 0
	}
	SessionIDLength := b[offset]
	offset += 1 + int(SessionIDLength)
	if offset+2 > len(b) {
		return 0, 0
	}
	CipherSuitersLength := binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2 + int(CipherSuitersLength)
	if offset >= len(b) {
		return 0, 0
	}
	CompressionMethodsLenght := b[offset]
	offset += 1 + int(CompressionMethodsLenght)
	if offset+2 > len(b) {
		return 0, 0
	}
	ExtensionsLength := binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2
	ExtensionsEnd := offset + int(ExtensionsLength)
	if ExtensionsEnd > len(b) {
		return 0, 0
	}
	for offset < ExtensionsEnd {
		ExtensionType := binary.BigEndian.Uint16(b[offset : offset+2])
		offset += 2
		ExtensionLength := binary.BigEndian.Uint16(b[offset : offset+2])
		offset += 2
		if ExtensionType == 0 {
			offset += 2
			offset++
			ServerNameLength := binary.BigEndian.Uint16(b[offset : offset+2])
			offset += 2
			return offset, int(ServerNameLength)
		} else {
			offset += int(ExtensionLength)
		}
	}
	return 0, 0
}

func GetQUICSNI(b []byte) string {
	if b[0] == 0x0d {
		if !(len(b) > 23 && string(b[9:13]) == "Q043") {
			return ""
		}
		if !(len(b) > 26 && b[26] == 0xa0) {
			return ""
		}

		if !(len(b) > 38 && string(b[30:34]) == "CHLO") {
			return ""
		}
		TagNum := int(binary.LittleEndian.Uint16(b[34:36]))

		BaseOffset := 38 + 8*TagNum
		if !(len(b) > BaseOffset) {
			return ""
		}

		var SNIOffset uint16 = 0
		for i := 0; i < TagNum; i++ {
			offset := 38 + i*8
			TagName := b[offset : offset+4]
			OffsetEnd := binary.LittleEndian.Uint16(b[offset+4 : offset+6])
			if bytes.Equal(TagName, []byte{'S', 'N', 'I', 0}) {
				if len(b[BaseOffset:]) < int(OffsetEnd) {
					return ""
				}
				return string(b[BaseOffset:][SNIOffset:OffsetEnd])
			} else {
				SNIOffset = OffsetEnd
			}
		}
	} else if b[0]&0xc0 == 0xc0 {
		if !(len(b) > 5) {
			return ""
		}
		Version := string(b[1:5])
		switch Version {
		case "Q046":
		case "Q050":
			return "" //TODO
		default:
			return ""
		}
		if !(len(b) > 31 && b[30] == 0xa0) {
			return ""
		}

		if !(len(b) > 42 && string(b[34:38]) == "CHLO") {
			return ""
		}
		TagNum := int(binary.LittleEndian.Uint16(b[38:40]))

		BaseOffset := 42 + 8*TagNum
		if !(len(b) > BaseOffset) {
			return ""
		}

		var SNIOffset uint16 = 0
		for i := 0; i < TagNum; i++ {
			offset := 42 + i*8
			TagName := b[offset : offset+4]
			OffsetEnd := binary.LittleEndian.Uint16(b[offset+4 : offset+6])
			if bytes.Equal(TagName, []byte{'S', 'N', 'I', 0}) {
				if len(b[BaseOffset:]) < int(OffsetEnd) {
					return ""
				}
				return string(b[BaseOffset:][SNIOffset:OffsetEnd])
			} else {
				SNIOffset = OffsetEnd
			}
		}
	}

	return ""
}

func HttpMove(conn net.Conn, host string, b []byte) bool {
	data := make([]byte, 1460)
	n := 0
	if host == "" {
		copy(data[:], []byte("HTTP/1.1 200 OK"))
		n += 15
	} else if host == "https" || host == "h3" {
		copy(data[:], []byte("HTTP/1.1 302 Found\r\nLocation: https://"))
		n += 38

		header := string(b)
		start := strings.Index(header, "Host: ")
		if start < 0 {
			return false
		}
		start += 6
		end := strings.Index(header[start:], "\r\n")
		if end < 0 {
			return false
		}
		end += start
		copy(data[n:], []byte(header[start:end]))
		n += end - start

		start = 4
		end = strings.Index(header[start:], " ")
		if end < 0 {
			return false
		}
		end += start
		copy(data[n:], []byte(header[start:end]))
		n += end - start
	} else {
		copy(data[:], []byte("HTTP/1.1 302 Found\r\nLocation: "))
		n += 30
		copy(data[n:], []byte(host))
		n += len(host)

		start := 4
		if start >= len(b) {
			return false
		}
		header := string(b)
		end := strings.Index(header[start:], " ")
		if end < 0 {
			return false
		}
		end += start
		copy(data[n:], []byte(header[start:end]))
		n += end - start
	}

	cache_control := []byte("\r\nCache-Control: private")
	copy(data[n:], cache_control)
	n += len(cache_control)

	if host == "h3" {
		alt_svc := []byte("\r\nAlt-Svc: h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000; persist=1")
		copy(data[n:], alt_svc)
		n += len(alt_svc)
	}

	content_length := []byte("\r\nContent-Length: 0\r\n\r\n")
	copy(data[n:], content_length)
	n += len(content_length)

	conn.Write(data[:n])
	return true
}

func DialStrip(host string, fronting string) (*tls.Conn, error) {
	var conf *tls.Config
	if fronting == "" {
		conf = &tls.Config{
			InsecureSkipVerify: true,
		}
	} else {
		conf = &tls.Config{
			ServerName:         fronting,
			InsecureSkipVerify: true,
		}
	}

	conn, err := tls.Dial("tcp", net.JoinHostPort(host, "443"), conf)
	return conn, err
}

func getMyIPv6() net.IP {
	s, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range s {
		strIP := strings.SplitN(a.String(), "/", 2)
		if strIP[1] == "128" && strIP[0] != "::1" {
			ip := net.ParseIP(strIP[0])
			ip4 := ip.To4()
			if ip4 == nil {
				return ip
			}
		}
	}
	return nil
}

func Init() {
	DomainMap = make(map[string]*PhantomServer)
}

func LoadConfig(filename string) error {
	conf, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer conf.Close()

	br := bufio.NewReader(conf)

	var option uint32 = 0
	var minTTL byte = 0
	var maxTTL byte = 0
	var syncMSS uint16 = 0
	server := ""
	device := ""

	var CurrentServer *PhantomServer = &PhantomServer{option, minTTL, maxTTL, syncMSS, server, device}

	for {
		line, _, err := br.ReadLine()
		if err == io.EOF {
			break
		}

		if len(line) > 0 {
			if line[0] != '#' {
				l := strings.SplitN(string(line), "#", 2)[0]
				keys := strings.SplitN(l, "=", 2)
				if len(keys) > 1 {
					if keys[0] == "server" {
						logPrintln(2, string(line))
						server = keys[1]
						CurrentServer = &PhantomServer{option, minTTL, maxTTL, syncMSS, server, device}
						if DefaultServer == nil {
							DefaultServer = CurrentServer
						}
					} else if keys[0] == "dns-min-ttl" {
						logPrintln(2, string(line))
						ttl, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						DNSMinTTL = uint32(ttl)

						CurrentServer = &PhantomServer{option, minTTL, maxTTL, syncMSS, server, device}
					} else if keys[0] == "method" {
						logPrintln(2, string(line))

						option = OPT_NONE
						methods := strings.Split(keys[1], ",")
						for _, m := range methods {
							method, ok := MethodMap[m]
							if ok {
								option |= method
							} else {
								logPrintln(1, "unsupported method: "+m)
							}
						}

						CurrentServer = &PhantomServer{option, minTTL, maxTTL, syncMSS, server, device}
					} else if keys[0] == "ttl" {
						logPrintln(2, string(line))

						ttl, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						minTTL = byte(ttl)

						CurrentServer = &PhantomServer{option, minTTL, maxTTL, syncMSS, server, device}
					} else if keys[0] == "mss" {
						logPrintln(2, string(line))

						mss, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						syncMSS = uint16(mss)

						CurrentServer = &PhantomServer{option, minTTL, maxTTL, syncMSS, server, device}
					} else if keys[0] == "max-ttl" {
						logPrintln(2, string(line))

						ttl, err := strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
						maxTTL = byte(ttl)

						CurrentServer = &PhantomServer{option, minTTL, maxTTL, syncMSS, server, device}
					} else if keys[0] == "device" {
						logPrintln(2, string(line))

						if keys[1] == "default" {
							device = ""
						} else {
							device = keys[1]
						}

						CurrentServer = &PhantomServer{option, minTTL, maxTTL, syncMSS, server, device}
					} else if keys[0] == "subdomain" {
						SubdomainDepth, err = strconv.Atoi(keys[1])
						if err != nil {
							log.Println(string(line), err)
							return err
						}
					} else if keys[0] == "tcpmapping" {
						mapping := strings.SplitN(keys[1], ">", 2)
						go TCPMapping(mapping[0], mapping[1])
					} else if keys[0] == "udpmapping" {
						mapping := strings.SplitN(keys[1], ">", 2)
						go UDPMapping(mapping[0], mapping[1])
					} else {
						ip := net.ParseIP(keys[0])
						var records *DNSRecords
						if strings.HasPrefix(keys[1], "[") {
							result, hasCache := DNSCache.Load(keys[1][1 : len(keys[1])-1])
							if hasCache {
								records = result.(*DNSRecords)
							} else {
								DomainMap[keys[0]] = CurrentServer
								return nil
							}
						} else {
							records = new(DNSRecords)
							if option != 0 {
								records.Index = len(Nose)
								records.Hint = uint(option)
								Nose = append(Nose, keys[0])
							}

							ips := strings.Split(keys[1], ",")
							for i := 0; i < len(ips); i++ {
								ip := net.ParseIP(ips[i])
								if ip == nil {
									log.Println(ips[i], "bad ip")
								}
								ip4 := ip.To4()
								if ip4 != nil {
									if records.A == nil {
										records.A = new(RecordAddresses)
									}
									records.A.Addresses = append(records.A.Addresses, ip4)
								} else {
									if records.AAAA == nil {
										records.AAAA = new(RecordAddresses)
									}
									records.AAAA.Addresses = append(records.AAAA.Addresses, ip)
								}
							}
						}

						if ip == nil {
							DomainMap[keys[0]] = CurrentServer
							DNSCache.Store(keys[0], records)
						} else {
							DomainMap[ip.String()] = CurrentServer
							DNSCache.Store(ip.String(), records)
						}
					}
				} else {
					addr, err := net.ResolveTCPAddr("tcp", keys[0])
					if err == nil {
						DomainMap[addr.String()] = CurrentServer
					} else {
						_, ipnet, err := net.ParseCIDR(keys[0])
						if err == nil {
							DomainMap[ipnet.String()] = CurrentServer
						} else {
							ip := net.ParseIP(keys[0])
							if ip != nil {
								DomainMap[ip.String()] = CurrentServer
							} else {
								DomainMap[keys[0]] = CurrentServer
								records := new(DNSRecords)
								if keys[0][0] != '.' && option != 0 {
									records.Index = len(Nose)
									records.Hint = uint(option)
									Nose = append(Nose, keys[0])
								}
								DNSCache.Store(ip.String(), records)
							}
						}
					}
				}
			}
		}
	}

	logPrintln(1, filename)

	return nil
}

func LoadHosts(filename string) error {
	hosts, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer hosts.Close()

	br := bufio.NewReader(hosts)

	for {
		line, _, err := br.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			logPrintln(1, err)
		}

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		k := strings.SplitN(string(line), "\t", 2)
		if len(k) == 2 {
			var records *DNSRecords

			name := k[1]
			_, ok := DNSCache.Load(name)
			if ok {
				continue
			}
			offset := 0
			for i := 0; i < SubdomainDepth; i++ {
				off := strings.Index(name[offset:], ".")
				if off == -1 {
					break
				}
				offset += off
				result, ok := DNSCache.Load(name[offset:])
				if ok {
					records = new(DNSRecords)
					*records = *result.(*DNSRecords)
					DNSCache.Store(name, records)
					continue
				}
				offset++
			}

			server := ConfigLookup(name)
			if ok && server.Option != 0 {
				records.Index = len(Nose)
				records.Hint = uint(server.Option)
				Nose = append(Nose, name)
			}
			ip := net.ParseIP(k[0])
			if ip == nil {
				fmt.Println(ip, "bad ip address")
				continue
			}
			ip4 := ip.To4()
			if ip4 != nil {
				records.A = &RecordAddresses{0x7FFFFFFFFFFFFFFF, []net.IP{ip4}}
			} else {
				records.AAAA = &RecordAddresses{0x7FFFFFFFFFFFFFFF, []net.IP{ip}}
			}
		}
	}

	return nil
}

func GetPAC(address string) string {
	rule := ""
	for host := range DomainMap {
		rule += fmt.Sprintf("\"%s\":1,\n", host)
	}
	Context := `var proxy = 'SOCKS %s';
var rules = {
%s}
function FindProxyForURL(url, host) {
	if (rules[host] != undefined) {
		return proxy;
	}
	for (var i = 0; i < %d; i++){
		var dot = host.indexOf(".");
		if (dot == -1) {return 'DIRECT';}
		host = host.slice(dot);
		if (rules[host] != undefined) {return proxy;}
		host = host.slice(1);
	}
	return 'DIRECT';
}
`
	return fmt.Sprintf(Context, address, rule, SubdomainDepth)
}
