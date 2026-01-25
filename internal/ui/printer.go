package ui

import (
	"github.com/K0NGR3SS/ghostweights/internal/models"
	"github.com/pterm/pterm"
)

func PrintFindings(findings []models.Finding) {
	if len(findings) == 0 {
		pterm.Success.Println("No Shadow AI artifacts found! Your cloud looks clean.")
		return
	}

	pterm.Warning.Printf("Found %d potential issues:\n\n", len(findings))

	// Updated headers to prioritize Description (Model/GPU info) over Port/IP
	data := [][]string{
		{"Risk", "Service", "Instance ID", "Description", "Evidence"},
	}

	for _, f := range findings {
		riskStyle := ""
		switch f.Risk {
		case models.RiskCritical:
			riskStyle = pterm.FgRed.Sprint("CRITICAL")
		case models.RiskHigh:
			riskStyle = pterm.FgRed.Sprint("HIGH")
		case models.RiskMedium:
			riskStyle = pterm.FgYellow.Sprint("MEDIUM")
		default:
			riskStyle = pterm.FgBlue.Sprint("LOW")
		}

		// Ensure Description isn't empty (fallback to NameTag or Port if needed)
		desc := f.Description
		if desc == "" {
			desc = f.NameTag
		}

		data = append(data, []string{
			riskStyle,
			pterm.FgCyan.Sprint(f.Service),
			f.InstanceID,
			desc,       // Now shows "Serving model: Llama-3... on GPU"
			f.Evidence, // Shows the raw command or open port detail
		})
	}

	// render table
	_ = pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func StartSpinner(text string) *pterm.SpinnerPrinter {
	spinner, _ := pterm.DefaultSpinner.Start(text)
	return spinner
}
func UpdateSpinner(spinner *pterm.SpinnerPrinter, text string) {
    if spinner != nil {
        spinner.UpdateText(text)
    }
}
