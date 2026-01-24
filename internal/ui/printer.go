package ui

import (
	"strconv"

	"github.com/K0NGR3SS/ghostweights/internal/models"
	"github.com/pterm/pterm"
)

func PrintFindings(findings []models.Finding) {
	if len(findings) == 0 {
		pterm.Success.Println("No Shadow AI artifacts found! Your cloud looks clean.")
		return
	}

	pterm.Warning.Printf("🚨 Found %d potential issues:\n\n", len(findings))

	data := [][]string{
		{"Risk", "Service", "Port", "Instance ID", "Name Tag", "Public IP"},
	}

	for _, f := range findings {
		riskStyle := ""
		switch f.Risk {
		case models.RiskCritical:
			riskStyle = pterm.FgRed.Sprint("CRITICAL")
		case models.RiskHigh:
			riskStyle = pterm.FgRed.Sprint("HIGH")
		case models.RiskMedium:
			riskStyle = pterm.FgYellow.Sprint("MED")
		default:
			riskStyle = pterm.FgBlue.Sprint("LOW")
		}

		data = append(data, []string{
			riskStyle,
			pterm.FgCyan.Sprint(f.Service),
			strconv.Itoa(int(f.Port)),
			f.InstanceID,
			f.NameTag,
			f.PublicIP,
		})
	}

	pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func StartSpinner(text string) *pterm.SpinnerPrinter {
	spinner, _ := pterm.DefaultSpinner.Start(text)
	return spinner
}
