package proxy

import (
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/chai2010/winsvc"

	ptcp "github.com/macronut/phantomsocks/phantomtcp"
)

func SetProxy(dev, address string, state bool) error {
	proxyAddr := strings.Split(address, "://")
	if len(proxyAddr) < 2 {
		return nil
	}

	proxyTCPAddr, err := net.ResolveTCPAddr("tcp", proxyAddr[1])
	if err != nil {
		return err
	}

	if state {
		switch proxyAddr[0] {
		case "redirect":
			if state {
				go ptcp.Redirect("6.0.0.1-6.0.255.254", proxyTCPAddr.Port, true)
				go ptcp.RedirectDNS()
			}

			arg := []string{"/flushdns"}
			cmd := exec.Command("ipconfig", arg...)
			_, err := cmd.CombinedOutput()
			if err != nil {
				return err
			}
		default:
			return nil
		}
	}

	return nil
}

func SetKeepAlive(conn net.Conn) error {
	return nil
}

var ServiceName string = "PhantomSocks"

func InstallService() {
	appPath, err := winsvc.GetAppPath()
	log.Println("Installing", appPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := winsvc.InstallService(appPath, ServiceName, ""); err != nil {
		log.Fatalf("installService(%s, %s): %v\n", ServiceName, "", err)
	}
	log.Printf(ServiceName, "installed\n")
}

func RemoveService() {
	if err := winsvc.RemoveService(ServiceName); err != nil {
		log.Fatalln("removeService:", err)
	}
	log.Printf(ServiceName, "removed\n")
}

func StartService() {
	if err := winsvc.StartService(ServiceName); err != nil {
		log.Fatalln("startService:", err)
	}
	log.Printf(ServiceName, "started\n")
}

func StopService() {
	if err := winsvc.StopService(ServiceName); err != nil {
		log.Fatalln("stopService:", err)
	}
	log.Printf(ServiceName, "stopped\n")
}

func RunAsService(start func()) bool {
	if !winsvc.IsAnInteractiveSession() {
		log.Println("main:", "runService")

		appPath, err := winsvc.GetAppPath()
		if err != nil {
			log.Fatal(err)
		}

		if err := os.Chdir(filepath.Dir(appPath)); err != nil {
			log.Fatal(err)
		}

		stop := func() {
			arg := []string{"/flushdns"}
			cmd := exec.Command("ipconfig", arg...)
			d, err := cmd.CombinedOutput()
			if err != nil {
				log.Println(string(d), err)
			}

			os.Exit(0)
		}

		if err := winsvc.RunAsService(ServiceName, start, stop, false); err != nil {
			log.Fatalf("svc.Run: %v\n", err)
		}
		return true
	}

	return false
}
