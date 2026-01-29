package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/K0NGR3SS/ghostweights/internal/models"
)

type SlackNotifier struct {
	WebhookURL string
	Channel    string
}

type slackMessage struct {
	Channel     string            `json:"channel,omitempty"`
	Username    string            `json:"username"`
	IconEmoji   string            `json:"icon_emoji"`
	Text        string            `json:"text"`
	Attachments []slackAttachment `json:"attachments"`
}

type slackAttachment struct {
	Color      string       `json:"color"`
	Title      string       `json:"title"`
	Text       string       `json:"text"`
	Fields     []slackField `json:"fields"`
	Footer     string       `json:"footer"`
	FooterIcon string       `json:"footer_icon"`
}

type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

func NewSlackNotifier(webhookURL, channel string) *SlackNotifier {
	return &SlackNotifier{
		WebhookURL: webhookURL,
		Channel:    channel,
	}
}

func (s *SlackNotifier) SendFindings(findings []models.Finding) error {
	if len(findings) == 0 {
		return s.sendCleanReport()
	}

	critical := filterByRisk(findings, models.RiskCritical)
	high := filterByRisk(findings, models.RiskHigh)
	medium := filterByRisk(findings, models.RiskMedium)
	low := filterByRisk(findings, models.RiskLow)

	text := fmt.Sprintf("🚨 *GhostWeights Scan Complete*\nFound *%d* Shadow AI findings", len(findings))

	attachments := []slackAttachment{
		{
			Color: "danger",
			Title: fmt.Sprintf("Summary (%d total findings)", len(findings)),
			Fields: []slackField{
				{Title: "Critical", Value: fmt.Sprintf("%d", len(critical)), Short: true},
				{Title: "High", Value: fmt.Sprintf("%d", len(high)), Short: true},
				{Title: "Medium", Value: fmt.Sprintf("%d", len(medium)), Short: true},
				{Title: "Low", Value: fmt.Sprintf("%d", len(low)), Short: true},
			},
			Footer:     "GhostWeights v1.0",
			FooterIcon: "https://platform.slack-edge.com/img/default_application_icon.png",
		},
	}

	if len(critical) > 0 {
		criticalText := ""
		for i, f := range critical {
			if i >= 5 {
				criticalText += fmt.Sprintf("\n_...and %d more_", len(critical)-5)
				break
			}
			criticalText += fmt.Sprintf("• *%s* on `%s` - %s\n", f.Service, f.InstanceID, f.Description)
		}

		attachments = append(attachments, slackAttachment{
			Color: "danger",
			Title: "🔴 Critical Findings",
			Text:  criticalText,
		})
	}

	if len(high) > 0 {
		highText := ""
		for i, f := range high {
			if i >= 5 {
				highText += fmt.Sprintf("\n_...and %d more_", len(high)-5)
				break
			}
			highText += fmt.Sprintf("• *%s* on `%s` - %s\n", f.Service, f.InstanceID, f.Description)
		}

		attachments = append(attachments, slackAttachment{
			Color: "warning",
			Title: "🟠 High Findings",
			Text:  highText,
		})
	}

	msg := slackMessage{
		Channel:     s.Channel,
		Username:    "GhostWeights",
		IconEmoji:   ":ghost:",
		Text:        text,
		Attachments: attachments,
	}

	return s.sendMessage(msg)
}

func (s *SlackNotifier) sendCleanReport() error {
	msg := slackMessage{
		Channel:   s.Channel,
		Username:  "GhostWeights",
		IconEmoji: ":white_check_mark:",
		Text:      "✅ *GhostWeights Scan Complete*\nNo Shadow AI artifacts found! Your cloud looks clean.",
	}

	return s.sendMessage(msg)
}

func (s *SlackNotifier) sendMessage(msg slackMessage) error {
	jsonData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal slack message: %w", err)
	}

	resp, err := http.Post(s.WebhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send slack message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned non-200 status: %d", resp.StatusCode)
	}

	return nil
}

func filterByRisk(findings []models.Finding, risk models.RiskLevel) []models.Finding {
	var filtered []models.Finding
	for _, f := range findings {
		if f.Risk == risk {
			filtered = append(filtered, f)
		}
	}
	return filtered
}