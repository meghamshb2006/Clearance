package audit

import (
	"fmt"
	"strings"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
)

// Enrich fills Title, Description, and Subject from event_type + metadata.
// Safe for historical rows that predate these API fields.
func Enrich(event domain.AuditEvent) domain.AuditEvent {
	meta := event.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	host := stringMeta(meta, "host")
	method := stringMeta(meta, "method")
	path := stringMeta(meta, "path")
	port := intMeta(meta, "port")
	destination := formatDestination(method, host, port, path)

	switch event.EventType {
	case "egress_pending":
		event.Title = "Egress held for review"
		event.Subject = destination
		event.Description = fmt.Sprintf(
			"An outbound %s request to %s was blocked by default-deny policy and placed in the approval inbox for human review.",
			fallback(method, "network"),
			fallback(formatHostPort(host, port), "an unknown host"),
		)
	case "egress_auto_approved":
		event.Title = "Egress auto-approved"
		event.Subject = destination
		ruleID := stringMeta(meta, "rule_id")
		if ruleID != "" {
			event.Description = fmt.Sprintf(
				"An outbound %s request to %s matched an existing allow rule and was permitted without operator action.",
				fallback(method, "network"),
				fallback(formatHostPort(host, port), "an unknown host"),
			)
		} else {
			event.Description = fmt.Sprintf(
				"An outbound %s request to %s was permitted by an allow rule.",
				fallback(method, "network"),
				fallback(formatHostPort(host, port), "an unknown host"),
			)
		}
	case "egress_approved_once":
		event.Title = "Operator approved once"
		event.Subject = destination
		event.Description = fmt.Sprintf(
			"An operator granted a one-time approval for %s to %s. The agent may retry this destination a single time.",
			fallback(method, "egress"),
			fallback(formatHostPort(host, port), "the requested host"),
		)
	case "egress_approved_once_consumed":
		event.Title = "One-time approval used"
		event.Subject = destination
		event.Description = fmt.Sprintf(
			"The agent consumed a prior one-time approval and completed %s to %s.",
			fallback(method, "egress"),
			fallback(formatHostPort(host, port), "the approved host"),
		)
	case "egress_approved_org_rule":
		event.Title = "Operator remembered for org"
		event.Subject = destination
		event.Description = fmt.Sprintf(
			"An operator approved %s to %s and created a persistent org allow rule so matching requests can auto-approve later.",
			fallback(method, "egress"),
			fallback(formatHostPort(host, port), "the requested host"),
		)
	case "egress_denied":
		event.Title = "Egress denied"
		event.Subject = destination
		feedback := stringMeta(meta, "feedback")
		if feedback == "" {
			feedback = stringMeta(meta, "error_message")
		}
		if feedback != "" {
			event.Description = fmt.Sprintf(
				"Egress to %s was denied. Reason: %s.",
				fallback(formatHostPort(host, port), "the requested host"),
				feedback,
			)
		} else {
			event.Description = fmt.Sprintf(
				"Egress to %s was denied by policy or an operator.",
				fallback(formatHostPort(host, port), "the requested host"),
			)
		}
	case "policy_rule_created":
		effect := stringMeta(meta, "effect")
		event.Title = "Policy rule created"
		event.Subject = destination
		event.Description = fmt.Sprintf(
			"A persistent %s rule was created for %s %s (path prefix %s).",
			fallback(effect, "policy"),
			fallback(method, "*"),
			fallback(formatHostPort(host, port), "host"),
			fallback(stringMeta(meta, "path_prefix"), "/"),
		)
	case "policy_rule_revoked":
		event.Title = "Policy rule revoked"
		event.Subject = destination
		if host != "" {
			event.Description = fmt.Sprintf(
				"A persistent policy rule for %s was revoked and will no longer auto-allow matching egress.",
				formatHostPort(host, port),
			)
		} else {
			event.Description = "A persistent policy rule was revoked and will no longer apply to matching egress."
		}
	default:
		event.Title = humanizeType(event.EventType)
		event.Subject = destination
		if destination != "" {
			event.Description = fmt.Sprintf("Control-plane event %q was recorded for %s.", event.EventType, destination)
		} else {
			event.Description = fmt.Sprintf("Control-plane event %q was recorded.", event.EventType)
		}
	}

	if event.ActorName == "" {
		if event.ActorID != nil && strings.TrimSpace(*event.ActorID) != "" {
			event.ActorName = "Operator"
		} else {
			event.ActorName = "System"
		}
	}
	return event
}

func EnrichAll(events []domain.AuditEvent) []domain.AuditEvent {
	out := make([]domain.AuditEvent, len(events))
	for i, event := range events {
		out[i] = Enrich(event)
	}
	return out
}

func stringMeta(meta map[string]any, key string) string {
	raw, ok := meta[key]
	if !ok || raw == nil {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func intMeta(meta map[string]any, key string) int {
	raw, ok := meta[key]
	if !ok || raw == nil {
		return 0
	}
	switch v := raw.(type) {
	case int:
		return v
	case int32:
		return int(v)
	case int64:
		return int(v)
	case float64:
		return int(v)
	case float32:
		return int(v)
	default:
		var n int
		_, _ = fmt.Sscanf(fmt.Sprint(v), "%d", &n)
		return n
	}
}

func formatHostPort(host string, port int) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if port > 0 && port != 443 && port != 80 {
		return fmt.Sprintf("%s:%d", host, port)
	}
	if port == 80 || port == 443 {
		return fmt.Sprintf("%s:%d", host, port)
	}
	return host
}

func formatDestination(method, host string, port int, path string) string {
	hp := formatHostPort(host, port)
	if hp == "" {
		return ""
	}
	parts := make([]string, 0, 3)
	if method != "" {
		parts = append(parts, method)
	}
	parts = append(parts, hp)
	if path != "" && path != "/" {
		parts = append(parts, path)
	}
	return strings.Join(parts, " ")
}

func fallback(value, def string) string {
	if strings.TrimSpace(value) == "" {
		return def
	}
	return value
}

func humanizeType(eventType string) string {
	eventType = strings.TrimSpace(eventType)
	if eventType == "" {
		return "Unknown event"
	}
	return strings.ReplaceAll(eventType, "_", " ")
}
