package tray

import (
	"fmt"

	"./icon"
	"github.com/getlantern/systray"
)

func Run() {
	onExit := func() {
	}

	systray.Run(onReady, onExit)
}

func onReady() {
	systray.SetTemplateIcon(icon.Data, icon.Data)
	systray.SetTitle("Phantomsocks")
	systray.SetTooltip("Phantomsocks")

	//mEnabled := systray.AddMenuItem("Stop", "Start/Stop Proxy")
	//systray.AddSeparator()
	mQuitOrig := systray.AddMenuItem("Quit", "Quit")

	//var running = true
	for {
		select {
		/*
			case <-mEnabled.ClickedCh:
				if running {
					mEnabled.SetTitle("Start")
					running = false
				} else {
					mEnabled.SetTitle("Stop")
					running = true
				}
		*/
		case <-mQuitOrig.ClickedCh:
			fmt.Println("Quit")
			systray.Quit()
		}
	}
}
