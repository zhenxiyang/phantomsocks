package phantomtcp

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func StartWireguard(config InterfaceConfig) (*netstack.Net, error) {
	var Address []netip.Addr
	for _, addr := range strings.Split(config.Address, ",") {
		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			logPrintln(0, addr, err)
			continue
		}
		Address = append(Address, prefix.Addr())
	}
	var DNS []netip.Addr
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
	MTU := int(config.MTU)
	tun, tnet, err := netstack.CreateNetTUN(Address, DNS, MTU)
	if err != nil {
		return nil, err
	}
	Logger := device.NewLogger(device.LogLevelSilent, "")
	if LogLevel == 1 {
		Logger = device.NewLogger(device.LogLevelError, "")
	} else if LogLevel > 1 {
		Logger = device.NewLogger(device.LogLevelVerbose, "")
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), Logger)

	PrivateKey, err := Base64ToHex(config.PrivateKey)
	if err != nil {
		return nil, err
	}

	for _, peer := range config.Peers {
		PublicKey, err := Base64ToHex(peer.PublicKey)
		if err != nil {
			return nil, err
		}
		PreSharedKey := "0000000000000000000000000000000000000000000000000000000000000000"
		if peer.PreSharedKey != "" {
			PreSharedKey, err = Base64ToHex(peer.PreSharedKey)
			if err != nil {
				return nil, err
			}
		}

		ipcRequest := fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
persistent_keepalive_interval=%d
preshared_key=%s`, PrivateKey, PublicKey, peer.Endpoint, peer.KeepAlive, PreSharedKey)

		for _, allowed_ip := range strings.Split(peer.AllowedIPs, ",") {
			if allowed_ip != "" {
				ipcRequest += fmt.Sprintf(`
allowed_ip=%s`, allowed_ip)
			}
		}

		logPrintln(4, ipcRequest)

		err = dev.IpcSet(ipcRequest)
		if err != nil {
			return nil, err
		}
	}

	err = dev.Up()
	if err != nil {
		return nil, err
	}

	return tnet, nil
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
