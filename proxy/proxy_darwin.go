package proxy

import (
	"io/ioutil"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

func RunCmd(cmd *exec.Cmd, arg ...string) (string, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	defer stdout.Close()

	if err := cmd.Start(); err != nil {
		return "", err
	}

	opBytes, err := ioutil.ReadAll(stdout)
	if err != nil {
		return "", err
	} else {
		return string(opBytes), nil
	}
}

func SetProxy(dev, address string, state bool) error {
	cmd := exec.Command("networksetup", "-listnetworkserviceorder")
	out, err := RunCmd(cmd)
	if err != nil {
		return err
	}

	proxyAddr := strings.Split(address, "://")
	if len(proxyAddr) < 2 {
		return nil
	}

	proxyProtocol := ""
	proxyState := ""

	switch proxyAddr[0] {
	case "http":
		proxyProtocol = "-setwebproxy"
		proxyState = "-setwebproxystate"
	case "socks":
		proxyProtocol = "-setsocksfirewallproxy"
		proxyState = "-setsocksfirewallproxystate"
	default:
		return nil
	}

	name := ""
	for _, networkservice := range strings.Split(out, "\n\n") {
		lines := strings.Split(networkservice, "\n")
		linesLen := len(lines)
		if linesLen < 2 {
			continue
		}

		_name := strings.Split(lines[linesLen-2], " ")
		_en := strings.Split(lines[linesLen-1], " ")
		name = _name[len(_name)-1]
		en := _en[len(_en)-1]
		en = en[:len(en)-1]

		if dev == en {
			break
		}
	}

	if state {
		addr, err := net.ResolveTCPAddr("tcp", proxyAddr[1])
		if err != nil {
			return err
		}

		cmd = exec.Command("networksetup", proxyProtocol, name, addr.IP.String(), strconv.Itoa(addr.Port))
		if err := cmd.Start(); err != nil {
			return err
		}
		cmd = exec.Command("networksetup", proxyState, name, "on")
		if err := cmd.Start(); err != nil {
			return err
		}
	} else {
		cmd := exec.Command("networksetup", proxyState, name, "off")
		if err := cmd.Start(); err != nil {
			return err
		}
	}

	return nil
}
