package store

import "testing"

func TestPersistentAllowMethodForCONNECT(t *testing.T) {
	method, path := persistentAllowMethod("CONNECT", "/ignored")
	if method != "*" || path != "/" {
		t.Fatalf("got method=%q path=%q, want *=/", method, path)
	}
	method, path = persistentAllowMethod("GET", "/zen")
	if method != "GET" || path != "/zen" {
		t.Fatalf("got method=%q path=%q", method, path)
	}
}
