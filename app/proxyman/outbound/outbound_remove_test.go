package outbound_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	. "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport"
)

type closeTrackingOutboundHandler struct {
	tag      string
	started  atomic.Int32
	closed   atomic.Int32
	onClose  func()
	closeErr error
}

func (h *closeTrackingOutboundHandler) Start() error {
	h.started.Add(1)
	return nil
}

func (h *closeTrackingOutboundHandler) Close() error {
	h.closed.Add(1)
	if h.onClose != nil {
		h.onClose()
	}
	return h.closeErr
}

func (h *closeTrackingOutboundHandler) Tag() string { return h.tag }

func (h *closeTrackingOutboundHandler) Dispatch(context.Context, *transport.Link) {}

func (h *closeTrackingOutboundHandler) SenderSettings() *serial.TypedMessage { return nil }

func (h *closeTrackingOutboundHandler) ProxySettings() *serial.TypedMessage { return nil }

func TestRemoveHandlerClosesExistingTaggedHandler(t *testing.T) {
	ctx := context.Background()
	manager, err := New(ctx, &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}

	first := &closeTrackingOutboundHandler{tag: "first"}
	second := &closeTrackingOutboundHandler{tag: "second"}
	if err := manager.AddHandler(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := manager.AddHandler(ctx, second); err != nil {
		t.Fatal(err)
	}

	if err := manager.RemoveHandler(ctx, "second"); err != nil {
		t.Fatal(err)
	}
	if second.closed.Load() != 1 {
		t.Fatalf("expected removed handler to be closed once, got %d", second.closed.Load())
	}
	if got := manager.GetHandler("second"); got != nil {
		t.Fatalf("expected removed handler lookup to be nil, got %T", got)
	}
	if first.closed.Load() != 0 {
		t.Fatalf("expected unrelated handler to remain open, got close count %d", first.closed.Load())
	}
	if manager.GetDefaultHandler() != first {
		t.Fatal("expected first handler to remain default")
	}
}

func TestRemoveHandlerClosesDefaultHandler(t *testing.T) {
	ctx := context.Background()
	manager, err := New(ctx, &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}

	handler := &closeTrackingOutboundHandler{tag: "default"}
	if err := manager.AddHandler(ctx, handler); err != nil {
		t.Fatal(err)
	}

	if err := manager.RemoveHandler(ctx, "default"); err != nil {
		t.Fatal(err)
	}
	if handler.closed.Load() != 1 {
		t.Fatalf("expected default handler to be closed once, got %d", handler.closed.Load())
	}
	if manager.GetDefaultHandler() != nil {
		t.Fatal("expected default handler to be cleared")
	}
}

func TestRemoveHandlerKeepsMissingTagIdempotent(t *testing.T) {
	ctx := context.Background()
	manager, err := New(ctx, &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}

	if err := manager.RemoveHandler(ctx, "missing"); err != nil {
		t.Fatalf("expected missing tag removal to remain idempotent, got %v", err)
	}
}

func TestRemoveHandlerClosesOutsideManagerLock(t *testing.T) {
	ctx := context.Background()
	manager, err := New(ctx, &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}

	closed := make(chan struct{})
	handler := &closeTrackingOutboundHandler{tag: "locked"}
	handler.onClose = func() {
		_ = manager.GetHandler("locked")
		close(closed)
	}
	if err := manager.AddHandler(ctx, handler); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- manager.RemoveHandler(ctx, "locked")
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("RemoveHandler appears to close the handler while holding manager lock")
	}

	select {
	case <-closed:
	default:
		t.Fatal("expected handler Close callback to run")
	}
}
