package phantomtcp

import (
	"errors"
	"io"
	"math/rand"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ConnectionInfo struct {
	Link gopacket.LinkLayer
	IP   gopacket.NetworkLayer
	TCP  layers.TCP
}

type SynInfo struct {
	Number uint32
	Option uint32
}

var ConnSyn sync.Map
var ConnInfo4 [65536]chan *ConnectionInfo
var ConnInfo6 [65536]chan *ConnectionInfo
var ConnWait4 [65536]uint32
var ConnWait6 [65536]uint32
var TFOCookies sync.Map
var TFOPayload [64][]byte
var TFOSynID uint8 = 0

const domainBytes = "abcdefghijklmnopqrstuvwxyz0123456789-"

func IsAddressInUse(err error) bool {
	//return errors.Is(err, syscall.EADDRINUSE)
	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	errSyscallError, ok := errOpError.Err.(*os.SyscallError)
	if !ok {
		return false
	}
	errErrno, ok := errSyscallError.Err.(syscall.Errno)
	if !ok {
		return false
	}
	if errErrno == syscall.EADDRINUSE {
		return true
	}
	return false
}

func IsNormalError(err error) bool {
	errOpError, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	switch e := errOpError.Err.(type) {
	case *os.SyscallError:
		errErrno, ok := e.Err.(syscall.Errno)
		if !ok {
			return false
		}

		if errErrno == syscall.ETIMEDOUT ||
			errErrno == syscall.ECONNREFUSED ||
			errErrno == syscall.ECONNRESET {
			return true
		}
	default:
		//logPrintln(2, reflect.TypeOf(e))
		return true
	}

	return false
}

func AddConn(synAddr string, option uint32) {
	result, ok := ConnSyn.LoadOrStore(synAddr, SynInfo{1, option})
	if ok {
		info := result.(SynInfo)
		info.Number++
		info.Option = option
		ConnSyn.Store(synAddr, info)
	}
}

func DelConn(synAddr string) {
	result, ok := ConnSyn.Load(synAddr)
	if ok {
		info := result.(SynInfo)
		if info.Number > 1 {
			info.Number--
			ConnSyn.Store(synAddr, info)
		} else {
			ConnSyn.Delete(synAddr)
		}
	}
}

func GetLocalAddr(name string, ipv6 bool) (*net.TCPAddr, error) {
	if name == "" {
		return nil, nil
	}

	inf, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, _ := inf.Addrs()
	for _, addr := range addrs {
		localAddr, ok := addr.(*net.IPNet)
		if ok {
			var laddr *net.TCPAddr
			ip4 := localAddr.IP.To4()
			if ipv6 {
				if ip4 != nil || localAddr.IP[0] == 0xfe {
					continue
				}
				ip := make([]byte, 16)
				copy(ip[:16], localAddr.IP)
				laddr = &net.TCPAddr{IP: ip[:], Port: 0}
			} else {
				if ip4 == nil {
					continue
				}
				ip := make([]byte, 4)
				copy(ip[:4], ip4)
				laddr = &net.TCPAddr{IP: ip[:], Port: 0}
			}

			return laddr, nil
		}
	}

	return nil, nil
}

func Dial(addresses []net.IP, port int, b []byte, conf *Config) (net.Conn, error) {
	var err error
	var conn net.Conn

	if conf == nil || b == nil {
		ip := addresses[rand.Intn(len(addresses))]
		raddr := &net.TCPAddr{IP: ip, Port: port, Zone: ""}
		conn, err = net.DialTCP("tcp", nil, raddr)
		if err != nil {
			return nil, err
		}
		if b != nil {
			_, err = conn.Write(b)
		}
		return conn, err
	}

	offset, length := GetSNI(b)

	if length > 0 {
		rand.Seed(time.Now().UnixNano())

		fakepaylen := 1280
		if len(b) < fakepaylen {
			fakepaylen = len(b)
		}
		fakepayload := make([]byte, fakepaylen)
		copy(fakepayload, b[:fakepaylen])

		min_dot := offset + length
		max_dot := offset
		for i := offset; i < offset+length; i++ {
			if fakepayload[i] == '.' {
				if i < min_dot {
					min_dot = i
				}
				if i > max_dot {
					max_dot = i
				}
			} else {
				fakepayload[i] = domainBytes[rand.Intn(len(domainBytes))]
			}
		}
		if min_dot == max_dot {
			min_dot = offset
		}
		cut := (min_dot + max_dot) / 2

		var tfo_payload []byte = nil
		if (conf.Option & (OPT_TFO | OPT_HTFO)) != 0 {
			if (conf.Option & OPT_TFO) != 0 {
				tfo_payload = b
			} else {
				tfo_payload = b[:cut]
			}
		}

		var synpacket *ConnectionInfo
		for i := 0; i < 5; i++ {
			ip := addresses[rand.Intn(len(addresses))]

			laddr, err := GetLocalAddr(conf.Device, ip.To4() == nil)
			if err != nil {
				return nil, errors.New("invalid device")
			}

			raddr := &net.TCPAddr{IP: ip, Port: port, Zone: ""}

			conn, synpacket, err = DialConnInfo(laddr, raddr, conf, tfo_payload)

			logPrintln(2, ip, port, err)
			if err != nil {
				if IsNormalError(err) {
					continue
				}
				return nil, err
			}

			break
		}

		if synpacket == nil {
			if conn != nil {
				conn.Close()
			}
			return nil, errors.New("connection does not exist")
		}

		synpacket.TCP.Seq++
		count := 1
		if (conf.Option & (OPT_TFO | OPT_HTFO)) != 0 {
			if (conf.Option & OPT_HTFO) != 0 {
				_, err = conn.Write(b[cut:])
				if err != nil {
					conn.Close()
					return nil, err
				}
			}
		} else {
			if conf.Option&OPT_SSEG != 0 {
				_, err = conn.Write(b[:4])
				if err != nil {
					conn.Close()
					return nil, err
				}
			}

			if conf.Option&OPT_MODE2 != 0 {
				synpacket.TCP.Seq += uint32(cut)
				fakepayload = fakepayload[cut:]
				count = 2
			} else {
				err = ModifyAndSendPacket(synpacket, fakepayload, conf.Option, conf.TTL, count)
				if err != nil {
					conn.Close()
					return nil, err
				}
			}

			if conf.Option&OPT_SSEG != 0 {
				_, err = conn.Write(b[4:cut])
			} else {
				_, err = conn.Write(b[:cut])
			}
			if err != nil {
				conn.Close()
				return nil, err
			}

			err = ModifyAndSendPacket(synpacket, fakepayload, conf.Option, conf.TTL, count)
			if err != nil {
				conn.Close()
				return nil, err
			}

			_, err = conn.Write(b[cut:])
			if err != nil {
				conn.Close()
				return nil, err
			}
		}

		return conn, err
	} else {
		ip := addresses[rand.Intn(len(addresses))]

		var laddr *net.TCPAddr = nil
		if conf.Device != "" {
			laddr, err = GetLocalAddr(conf.Device, ip.To4() == nil)
			if err != nil {
				return nil, err
			}
		}

		raddr := &net.TCPAddr{IP: ip, Port: port, Zone: ""}
		conn, err = net.DialTCP("tcp", laddr, raddr)
		if err != nil {
			return nil, err
		}
		_, err = conn.Write(b)
		if err != nil {
			conn.Close()
		}
		return conn, err
	}
}

func HTTP(client net.Conn, addresses []net.IP, port int, b []byte, conf *Config) (net.Conn, error) {
	var err error
	var conn net.Conn

	if b != nil {
		offset, length := GetHost(b)

		if length > 0 {
			rand.Seed(time.Now().UnixNano())

			fakepaylen := 1280
			if len(b) < fakepaylen {
				fakepaylen = len(b)
			}
			fakepayload := make([]byte, fakepaylen)
			copy(fakepayload, b[:fakepaylen])

			min_dot := offset + length
			max_dot := offset
			for i := offset; i < offset+length; i++ {
				if fakepayload[i] == '.' {
					if i < min_dot {
						min_dot = i
					}
					if i > max_dot {
						max_dot = i
					}
				} else {
					fakepayload[i] = domainBytes[rand.Intn(len(domainBytes))]
				}
			}
			if min_dot == max_dot {
				min_dot = offset
			}
			cut := (min_dot + max_dot) / 2

			var connInfo *ConnectionInfo
			for i := 0; i < 5; i++ {
				ip := addresses[rand.Intn(len(addresses))]

				laddr, err := GetLocalAddr(conf.Device, ip.To4() == nil)
				if err != nil {
					continue
				}

				raddr := &net.TCPAddr{IP: ip, Port: port, Zone: ""}
				conn, connInfo, err = DialConnInfo(laddr, raddr, conf, nil)
				logPrintln(2, ip, port, err)
				if err != nil {
					if IsNormalError(err) {
						continue
					}
					return nil, err
				}
			}

			if connInfo == nil {
				return nil, errors.New("connection does not exist")
			}

			count := 1
			if conf.Option&OPT_MODE2 == 0 {
				err = ModifyAndSendPacket(connInfo, fakepayload, conf.Option, conf.TTL, 1)
				if err != nil {
					conn.Close()
					return nil, err
				}
			} else {
				connInfo.TCP.Seq += uint32(cut)
				fakepayload = fakepayload[cut:]
				count = 2
			}

			_, err = conn.Write(b[:cut])
			if err != nil {
				conn.Close()
				return nil, err
			}

			err = ModifyAndSendPacket(connInfo, fakepayload, conf.Option, conf.TTL, count)
			if err != nil {
				conn.Close()
				return nil, err
			}

			_, err = conn.Write(b[cut:])
			if err != nil {
				conn.Close()
				return nil, err
			}

			connInfo.TCP.Seq += uint32(len(b))
			go func() {
				var b [1460]byte
				for {
					n, err := client.Read(b[:])
					if err != nil {
						conn.Close()
						return
					}

					err = ModifyAndSendPacket(connInfo, fakepayload, conf.Option, conf.TTL, 2)
					if err != nil {
						conn.Close()
						return
					}
					_, err = conn.Write(b[:n])
					if err != nil {
						conn.Close()
						return
					}
					connInfo.TCP.Seq += uint32(n)
				}
			}()

			return conn, err
		} else {
			ip := addresses[rand.Intn(len(addresses))]

			var laddr *net.TCPAddr = nil
			if conf.Device != "" {
				laddr, err = GetLocalAddr(conf.Device, ip.To4() == nil)
				if err != nil {
					return nil, err
				}
			}

			raddr := &net.TCPAddr{IP: ip, Port: port, Zone: ""}
			conn, err = net.DialTCP("tcp", laddr, raddr)
			if err != nil {
				return nil, err
			}
			_, err = conn.Write(b)
			if err != nil {
				conn.Close()
				return conn, err
			}
			go io.Copy(conn, client)
			return conn, err
		}
	}

	ip := addresses[rand.Intn(len(addresses))]
	raddr := &net.TCPAddr{IP: ip, Port: port, Zone: ""}
	conn, err = net.DialTCP("tcp", nil, raddr)
	if err != nil {
		return conn, err
	}

	go io.Copy(conn, client)
	return conn, err
}
