package phantomtcp

import (
	"errors"
	"io"
	"math/rand"
	"net"
	"os"
	"syscall"
	"time"
)

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
	errSyscallError, ok := errOpError.Err.(*os.SyscallError)
	if !ok {
		return false
	}
	errErrno, ok := errSyscallError.Err.(syscall.Errno)
	if !ok {
		return false
	}
	if errErrno == syscall.ECONNREFUSED ||
		errErrno == syscall.ECONNRESET {
		return true
	}
	return false
}

func AddConn(synAddr string) {
	SynLock.Lock()
	ConnSyn[synAddr]++
	SynLock.Unlock()
}

func DelConn(synAddr string) {
	SynLock.Lock()
	synCount, _ := ConnSyn[synAddr]
	synCount--
	if synCount != 0 {
		ConnSyn[synAddr] = synCount
	} else {
		delete(ConnSyn, synAddr)
	}
	SynLock.Unlock()
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
		raddr := &net.TCPAddr{ip, port, ""}
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

		if conf.Option&OPT_SSEG != 0 {
			ip := addresses[rand.Intn(len(addresses))]
			raddr := &net.TCPAddr{ip, port, ""}
			if (conf.Option & OPT_HTFO) != 0 {
				conn, _, err = DialConnInfo(nil, raddr, conf, nil)
			} else {
				conn, err = net.DialTCP("tcp", nil, raddr)
			}
			if err != nil {
				return nil, err
			}

			_, err = conn.Write(b[:6])
			_, err = conn.Write(b[6:cut])
			_, err = conn.Write(b[cut:])
			if err != nil {
				conn.Close()
				return nil, err
			}
		} else {
			var connInfo *ConnectionInfo
			for i := 0; i < 5; i++ {
				ip := addresses[rand.Intn(len(addresses))]

				laddr, err := GetLocalAddr(conf.Device, ip.To4() == nil)
				if err != nil {
					return nil, errors.New("invalid device")
				}

				raddr := &net.TCPAddr{ip, port, ""}
				if (conf.Option & (OPT_TFO | OPT_HTFO)) != 0 {
					if (conf.Option & OPT_TFO) != 0 {
						conn, connInfo, err = DialConnInfo(laddr, raddr, conf, b)
					} else {
						conn, connInfo, err = DialConnInfo(laddr, raddr, conf, b[:cut])
					}
				} else {
					conn, connInfo, err = DialConnInfo(laddr, raddr, conf, nil)
				}

				logPrintln(2, ip, port, err)
				if err != nil {
					if IsNormalError(err) {
						continue
					}
					return nil, err
				}

				break
			}

			if connInfo == nil {
				if conn != nil {
					conn.Close()
				}
				return nil, errors.New("connection does not exist")
			}

			count := 1
			if (conf.Option & OPT_TFO) != 0 {
				if len(connInfo.TCP.Payload) == 0 {
					conn.Close()
					return nil, errors.New("invalid tcp fastopen connection")
				}
			} else {
				if conf.Option&OPT_HTFO != 0 {
					if len(connInfo.TCP.Payload) > 0 {
						count = 0
					} else {
						connInfo.TCP.Seq += uint32(cut)
						fakepayload = fakepayload[cut:]
						count = 2
					}
				} else {
					if conf.Option&OPT_MODE2 == 0 {
						err = SendFakePacket(connInfo, fakepayload, conf, count)
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
				}

				err = SendFakePacket(connInfo, fakepayload, conf, count)
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

		raddr := &net.TCPAddr{ip, port, ""}
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

	return conn, err
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

				raddr := &net.TCPAddr{ip, port, ""}
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
			if conf.Option&OPT_HTFO != 0 {
				count = 2
			} else {
				if conf.Option&OPT_MODE2 == 0 {
					err = SendFakePacket(connInfo, fakepayload, conf, 1)
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
			}

			err = SendFakePacket(connInfo, fakepayload, conf, count)
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

					err = SendFakePacket(connInfo, fakepayload, conf, 2)
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

			raddr := &net.TCPAddr{ip, port, ""}
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
	raddr := &net.TCPAddr{ip, port, ""}
	conn, err = net.DialTCP("tcp", nil, raddr)
	if err != nil {
		return conn, err
	}

	go io.Copy(conn, client)
	return conn, err
}
