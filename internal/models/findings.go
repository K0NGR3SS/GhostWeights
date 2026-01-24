package models

type RiskLevel string

const (
	RiskCritical RiskLevel = "CRITICAL" // RCE possible (e.g. open Ollama)
	RiskHigh     RiskLevel = "HIGH"     // Data leak possible (e.g. Streamlit)
	RiskMedium   RiskLevel = "MEDIUM" 
	RiskLow      RiskLevel = "LOW"
)

type Finding struct {
	InstanceID   string    `json:"instance_id"`
	Region       string    `json:"region"`
	PublicIP     string    `json:"public_ip"`
	PrivateIP    string    `json:"private_ip"`
	NameTag      string    `json:"name_tag"`
	Risk         RiskLevel `json:"risk"`
	Service      string    `json:"service"`
	Port         int32     `json:"port"`
	Description  string    `json:"description"`
	Evidence     string    `json:"evidence"`
}