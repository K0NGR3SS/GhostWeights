package models

type RiskLevel string

const (
	RiskCritical RiskLevel = "CRITICAL" // RCE possible (e.g. open Ollama)
	RiskHigh     RiskLevel = "HIGH"     // Data leak possible (e.g. Streamlit)
	RiskMedium   RiskLevel = "MEDIUM"
	RiskLow      RiskLevel = "LOW"
)

type Finding struct {
	InstanceID  string    `json:"instance_id"`
	Region      string    `json:"region"`
	PublicIP    string    `json:"public_ip,omitempty"`
	PrivateIP   string    `json:"private_ip,omitempty"`
	NameTag     string    `json:"name_tag,omitempty"`
	Risk        RiskLevel `json:"risk"`
	Service     string    `json:"service"`
	Port        int32     `json:"port,omitempty"`
	Description string    `json:"description,omitempty"`
	Evidence    string    `json:"evidence,omitempty"`
}