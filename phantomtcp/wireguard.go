package phantomtcp

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func WireGuardServer(service ServiceConfig) {
	laddr, err := net.ResolveUDPAddr("udp", service.Address)
	if err != nil {
		logPrintln(0, service, err)
	}

	vaddr := [4]byte{VirtualAddrPrefix, 0, 0, 0}
	prefix := netip.PrefixFrom(netip.AddrFrom4(vaddr), 32)
	tun, tnet, err := StartWireguard([]netip.Addr{prefix.Addr()}, laddr.Port, nil, service.MTU, service.PrivateKey, service.Peers)
	if err != nil {
		logPrintln(0, service, err)
	}

	go func() {
		addr, err := net.ResolveTCPAddr("tcp", "0.0.0.0:443")
		l, err := tnet.ListenTCP(addr)
		if err != nil {
			logPrintln(0, service, err)
		}
		for {
			client, err := l.Accept()
			if err != nil {
				logPrintln(1, err)
			}
			switch addr := client.LocalAddr().(type) {
			case *net.TCPAddr:
				go redirect(client, &net.TCPAddr{IP: addr.IP.To4(), Port: addr.Port})
			}
		}
	}()

	go func() {
		addr, err := net.ResolveTCPAddr("tcp", "0.0.0.0:80")
		l, err := tnet.ListenTCP(addr)
		if err != nil {
			logPrintln(0, service, err)
		}
		for {
			client, err := l.Accept()
			if err != nil {
				logPrintln(1, err)
			}
			go SNIProxy(client)
		}
	}()

	l, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(netip.AddrFrom4(vaddr), 53))
	if err != nil {
		logPrintln(0, service, err)
	}

	var buf [512]byte
	for {
		n, raddr, err := l.ReadFrom(buf[:])
		if err != nil {
			continue
		}

		index, response := NSRequest(buf[:n], true)
		vaddr := [4]byte{VirtualAddrPrefix, 0, byte(index >> 8), byte(index & 0xFF)}
		prefix := netip.PrefixFrom(netip.AddrFrom4(vaddr), 32)
		netstack.AddAddress(tun, prefix.Addr())

		l.WriteTo(response, raddr)
	}
}

func WireGuardClient(client InterfaceConfig) (*netstack.Net, error) {
	var addrs []netip.Addr
	for _, addr := range strings.Split(client.Address, ",") {
		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			logPrintln(0, addr, err)
			continue
		}
		addrs = append(addrs, prefix.Addr())
	}
	_, tnet, err := StartWireguard(addrs, 0, nil, int(client.MTU), client.PrivateKey, client.Peers)
	return tnet, err
}

func StartWireguard(Addresses []netip.Addr, ListenPort int, DNS []netip.Addr, MTU int, PrivateKey string, Peers []Peer) (tun.Device, *netstack.Net, error) {
	/*
		for _, addr := range strings.Split(config.DNS, ",") {
			prefix, err := netip.ParsePrefix(addr)
			if err != nil {
				logPrintln(0, addr, err)
				continue
			}
			DNS = append(DNS, prefix.Addr())
		}
	*/
	tun, tnet, err := netstack.CreateNetTUN(Addresses, DNS, MTU)
	if err != nil {
		return nil, nil, err
	}
	Logger := device.NewLogger(device.LogLevelSilent, "")
	if LogLevel == 1 {
		Logger = device.NewLogger(device.LogLevelError, "")
	} else if LogLevel > 1 {
		Logger = device.NewLogger(device.LogLevelVerbose, "")
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), Logger)

	PrivateKey, err = Base64ToHex(PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	ipcRequest := fmt.Sprintf("private_key=%s", PrivateKey)
	if ListenPort != 0 {
		ipcRequest += fmt.Sprintf(`
listen_port=%d`, ListenPort)
	}

	err = dev.IpcSet(ipcRequest)
	if err != nil {
		return nil, nil, err
	}

	for _, peer := range Peers {
		PublicKey, err := Base64ToHex(peer.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		PreSharedKey := "0000000000000000000000000000000000000000000000000000000000000000"
		if peer.PreSharedKey != "" {
			PreSharedKey, err = Base64ToHex(peer.PreSharedKey)
			if err != nil {
				return nil, nil, err
			}
		}

		ipcRequest := fmt.Sprintf(`public_key=%s
persistent_keepalive_interval=%d
preshared_key=%s`, PublicKey, peer.KeepAlive, PreSharedKey)

		if peer.Endpoint != "" {
			ipcRequest += fmt.Sprintf(`
endpoint=%s`, peer.Endpoint)
		}

		for _, allowed_ip := range strings.Split(peer.AllowedIPs, ",") {
			if allowed_ip != "" {
				ipcRequest += fmt.Sprintf(`
allowed_ip=%s`, allowed_ip)
			}
		}

		logPrintln(4, ipcRequest)

		err = dev.IpcSet(ipcRequest)
		if err != nil {
			return nil, nil, err
		}
	}

	err = dev.Up()
	if err != nil {
		return nil, nil, err
	}

	return tun, tnet, nil
}

func Base64ToHex(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", errors.New("invalid base64 string: " + key)
	}
	if len(decoded) != 32 {
		return "", errors.New("key should be 32 bytes: " + key)
	}
	return hex.EncodeToString(decoded), nil
}
