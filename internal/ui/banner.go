package ui

import (
	"time"

	"github.com/pterm/pterm"
)

func PrintBanner() {
	logo := `
   ________               __ _       __     _       __    __          
  / ____/ /_  ____  _____/ /| |     / /__  (_)___  / /_ _/ /_ ____  
 / / __/ __ \/ __ \/ ___/ __/ | /| / / _ \/ / __ \/ _  \  __ / __/
/ /_/ / / / / /_/ (__  ) /_ | |/ |/ /  __/ / /_/ / / / / /_ (__ )     
\____/_/ /_/\____/____/\__/ |__/|__/\___/_/\__, /_/ /_/\__/____/      
                                          /____/
`
	pterm.FgRed.Println(logo)
	pterm.DefaultCenter.Println(pterm.FgGray.Sprint("v1.0 - Shadow AI Hunter"))
	pterm.Println()

	pterm.DefaultBox.
		WithTitle(pterm.FgYellow.Sprint("⚠️  WARNING: AUTHORIZED USE ONLY ⚠️")).
		WithTitleBottomCenter().
		WithRightPadding(2).
		WithLeftPadding(2).
		Println("This tool is designed for security auditing of infrastructure YOU OWN.\nScanning unauthorized targets is illegal.")
	
	pterm.Println()
	time.Sleep(1 * time.Second)
}
