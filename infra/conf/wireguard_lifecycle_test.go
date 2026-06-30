package conf_test

import (
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/wireguard"
)

func testWireGuardConfig() *WireGuardConfig {
	return &WireGuardConfig{
		IsClient:    true,
		NoKernelTun: true,
		SecretKey:   strings.Repeat("01", 32),
		Address:     []string{"10.0.0.2/32"},
		Peers: []*WireGuardPeerConfig{{
			PublicKey:  strings.Repeat("02", 32),
			Endpoint:   "127.0.0.1:51820",
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		}},
	}
}

func TestWireGuardLifecycleDefaultsToPersistent(t *testing.T) {
	msg, err := testWireGuardConfig().Build()
	if err != nil {
		t.Fatal(err)
	}
	config := msg.(*wireguard.DeviceConfig)
	if config.Lifecycle != wireguard.DeviceConfig_PERSISTENT {
		t.Fatalf("expected persistent lifecycle, got %v", config.Lifecycle)
	}
	if config.MinReconnectIntervalMs != 0 {
		t.Fatalf("expected default min reconnect interval 0, got %d", config.MinReconnectIntervalMs)
	}
	if config.MaxConcurrentSessions != 0 {
		t.Fatalf("expected default max concurrent sessions 0, got %d", config.MaxConcurrentSessions)
	}
}

func TestWireGuardLifecyclePerConnectionBuild(t *testing.T) {
	input := testWireGuardConfig()
	input.Lifecycle = "per_connection"
	input.MinReconnectIntervalMs = 3000
	input.MaxConcurrentSessions = 2

	msg, err := input.Build()
	if err != nil {
		t.Fatal(err)
	}
	config := msg.(*wireguard.DeviceConfig)
	if config.Lifecycle != wireguard.DeviceConfig_PER_CONNECTION {
		t.Fatalf("expected perConnection lifecycle, got %v", config.Lifecycle)
	}
	if config.MinReconnectIntervalMs != 3000 {
		t.Fatalf("expected min reconnect interval 3000, got %d", config.MinReconnectIntervalMs)
	}
	if config.MaxConcurrentSessions != 2 {
		t.Fatalf("expected max concurrent sessions 2, got %d", config.MaxConcurrentSessions)
	}
}

func TestWireGuardLifecyclePerConnectionDefaultsConcurrency(t *testing.T) {
	input := testWireGuardConfig()
	input.Lifecycle = "perConnection"

	msg, err := input.Build()
	if err != nil {
		t.Fatal(err)
	}
	config := msg.(*wireguard.DeviceConfig)
	if config.MaxConcurrentSessions != 1 {
		t.Fatalf("expected perConnection max concurrent sessions to default to 1, got %d", config.MaxConcurrentSessions)
	}
}

func TestWireGuardLifecyclePerConnectionRejectsServerMode(t *testing.T) {
	input := testWireGuardConfig()
	input.IsClient = false
	input.Lifecycle = "perConnection"

	if _, err := input.Build(); err == nil || !strings.Contains(err.Error(), "only supported for client outbound") {
		t.Fatalf("expected client outbound validation error, got %v", err)
	}
}

func TestWireGuardLifecyclePerConnectionRequiresNoKernelTun(t *testing.T) {
	input := testWireGuardConfig()
	input.NoKernelTun = false
	input.Lifecycle = "perConnection"

	if _, err := input.Build(); err == nil || !strings.Contains(err.Error(), "requires noKernelTun=true") {
		t.Fatalf("expected noKernelTun validation error, got %v", err)
	}
}

func TestWireGuardLifecycleRejectsReservedAndUnknownValues(t *testing.T) {
	for _, lifecycle := range []string{"idleTimeout", "idle_timeout", "unexpected"} {
		input := testWireGuardConfig()
		input.Lifecycle = lifecycle
		if _, err := input.Build(); err == nil {
			t.Fatalf("expected lifecycle %q to be rejected", lifecycle)
		}
	}
}

func TestWireGuardLifecycleRejectsNegativeLimits(t *testing.T) {
	tests := []struct {
		name string
		edit func(*WireGuardConfig)
	}{
		{
			name: "negative interval",
			edit: func(c *WireGuardConfig) { c.MinReconnectIntervalMs = -1 },
		},
		{
			name: "negative concurrency",
			edit: func(c *WireGuardConfig) { c.MaxConcurrentSessions = -1 },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := testWireGuardConfig()
			tc.edit(input)
			if _, err := input.Build(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
