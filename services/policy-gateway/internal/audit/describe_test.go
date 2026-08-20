package audit_test

import (
	"strings"
	"testing"

	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/audit"
	"github.com/meghamshb2006/clearance/services/policy-gateway/internal/domain"
)

func TestEnrichPendingHasRealDescription(t *testing.T) {
	event := audit.Enrich(domain.AuditEvent{
		EventType: "egress_pending",
		Metadata: map[string]any{
			"host":   "api.github.com",
			"port":   443,
			"method": "CONNECT",
			"path":   "/",
		},
	})
	if event.Title == "" || event.Description == "" {
		t.Fatalf("missing title/description: %+v", event)
	}
	if event.Subject == "" {
		t.Fatal("expected subject")
	}
	if !strings.Contains(event.Description, "api.github.com") {
		t.Fatalf("description should mention host: %s", event.Description)
	}
	if !strings.Contains(event.Description, "approval inbox") {
		t.Fatalf("description should explain pending review: %s", event.Description)
	}
}

func TestEnrichDenyIncludesFeedback(t *testing.T) {
	event := audit.Enrich(domain.AuditEvent{
		EventType: "egress_denied",
		Metadata: map[string]any{
			"host":     "httpbin.org",
			"port":     443,
			"method":   "GET",
			"feedback": "policy_violation",
		},
	})
	if !strings.Contains(event.Description, "policy_violation") {
		t.Fatalf("expected feedback in description: %s", event.Description)
	}
}
