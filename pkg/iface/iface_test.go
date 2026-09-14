package iface

import (
	"testing"
)

func TestResolveInterfaceIP(t *testing.T) {
	// Empty string should bind to all (return "")
	ip, err := ResolveInterfaceIP("")
	if err != nil {
		t.Fatalf("expected no error for empty input, got: %v", err)
	}
	if ip != "" {
		t.Errorf("expected empty string for all interfaces, got: %s", ip)
	}

	// Direct IP string
	ip, err = ResolveInterfaceIP("127.0.0.1")
	if err != nil {
		t.Fatalf("expected no error for 127.0.0.1, got: %v", err)
	}
	if ip != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got: %s", ip)
	}
}
