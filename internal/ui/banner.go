package ui

import (
	"fmt"
	"time"

	"github.com/fatih/color"
)

func PrintBanner() {
	redLogo := color.New(color.FgRed, color.Bold).SprintFunc()
	logo := `
   ________               __ _       __     _       __    __          
  / ____/ /_  ____  _____/ /| |     / /__  (_)___  / /_ _/ /_ ____  
 / / __/ __ \/ __ \/ ___/ __/ | /| / / _ \/ / __ \/ _  \  __ / __/
/ /_/ / / / / /_/ (__  ) /_ | |/ |/ /  __/ / /_/ / / / / /_ (__ )     
\____/_/ /_/\____/____/\__/ |__/|__/\___/_/\__, /_/ /_/\__/____/      
                                          /____/
`

	fmt.Printf("%s\n", redLogo(logo))

	warningColor := color.New(color.FgYellow, color.Bold).SprintFunc() 
	fmt.Println(warningColor("⚠️  WARNING: AUTHORIZED USE ONLY ⚠️"))
	fmt.Println("This tool is designed for security auditing of infrastructure YOU OWN.")
	fmt.Println("Scanning unauthorized targets is illegal and punishable by law.")
	fmt.Println("---------------------------------------------------------------")
	
	time.Sleep(1 * time.Second)
}