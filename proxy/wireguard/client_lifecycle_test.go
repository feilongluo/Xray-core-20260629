package wireguard

import (
	"context"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

type fakeTunDevice struct {
	closed atomic.Int32
	events chan tun.Event
}

func newFakeTunDevice() *fakeTunDevice {
	return &fakeTunDevice{events: make(chan tun.Event)}
}

func (d *fakeTunDevice) File() *os.File { return nil }

func (d *fakeTunDevice) Read(_ [][]byte, _ []int, _ int) (int, error) { return 0, io.EOF }

func (d *fakeTunDevice) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }

func (d *fakeTunDevice) MTU() (int, error) { return 1420, nil }

func (d *fakeTunDevice) Name() (string, error) { return "fake0", nil }

func (d *fakeTunDevice) Events() <-chan tun.Event { return d.events }

func (d *fakeTunDevice) Close() error {
	d.closed.Add(1)
	return nil
}

func (d *fakeTunDevice) BatchSize() int { return 1 }

func TestWGSessionCloseIsIdempotentBeforeDeviceInit(t *testing.T) {
	tunDevice := newFakeTunDevice()
	session := &wgSession{tun: tunDevice}

	if session.IsClosed() {
		t.Fatal("expected session with an open TUN to be reported as open")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}

	if tunDevice.closed.Load() != 1 {
		t.Fatalf("expected TUN to close once, got %d", tunDevice.closed.Load())
	}
	if !session.IsClosed() {
		t.Fatal("expected session to be reported as closed")
	}
	_, _, closed := session.resources()
	if !closed {
		t.Fatal("expected session resources snapshot to report closed")
	}
}

func TestHandlerCloseClosesPersistentAndActiveSessions(t *testing.T) {
	persistentTun := newFakeTunDevice()
	activeTun := newFakeTunDevice()
	activeSession := &wgSession{tun: activeTun}
	handler := &Handler{
		conf:           &DeviceConfig{},
		persistent:     &wgSession{tun: persistentTun},
		activeSessions: map[*wgSession]struct{}{activeSession: {}},
		closedCh:       make(chan struct{}),
	}

	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}

	if persistentTun.closed.Load() != 1 {
		t.Fatalf("expected persistent TUN to close once, got %d", persistentTun.closed.Load())
	}
	if activeTun.closed.Load() != 1 {
		t.Fatalf("expected active TUN to close once, got %d", activeTun.closed.Load())
	}
	if handler.persistent != nil {
		t.Fatal("expected persistent session to be cleared")
	}
	if len(handler.activeSessions) != 0 {
		t.Fatalf("expected active sessions to be cleared, got %d", len(handler.activeSessions))
	}
	if err := handler.registerActiveSession(&wgSession{tun: newFakeTunDevice()}); err == nil {
		t.Fatal("expected registering a session after Close to fail")
	}
}

func TestHandlerCloseAllowsNilClosedChannel(t *testing.T) {
	tunDevice := newFakeTunDevice()
	handler := &Handler{persistent: &wgSession{tun: tunDevice}}

	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	if tunDevice.closed.Load() != 1 {
		t.Fatalf("expected persistent TUN to close once, got %d", tunDevice.closed.Load())
	}
}

func TestAcquireSessionSlotLimitsConcurrency(t *testing.T) {
	handler := &Handler{
		conf:           &DeviceConfig{},
		closedCh:       make(chan struct{}),
		activeSessions: map[*wgSession]struct{}{},
		sessionLimiter: make(chan struct{}, 1),
	}

	release, err := handler.acquireSessionSlot(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := handler.acquireSessionSlot(ctx); err == nil {
		t.Fatal("expected second acquisition to wait until context deadline")
	}

	release()
	secondRelease, err := handler.acquireSessionSlot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secondRelease()
}

func TestWaitReconnectIntervalHonorsLastCloseTime(t *testing.T) {
	handler := &Handler{
		conf:           &DeviceConfig{MinReconnectIntervalMs: 30},
		closedCh:       make(chan struct{}),
		activeSessions: map[*wgSession]struct{}{},
		lastCloseAt:    time.Now(),
	}

	started := time.Now()
	if err := handler.waitReconnectInterval(context.Background()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 20*time.Millisecond {
		t.Fatalf("expected reconnect interval wait, elapsed %s", elapsed)
	}
}

func TestWaitReconnectIntervalStopsWhenHandlerCloses(t *testing.T) {
	handler := &Handler{
		conf:           &DeviceConfig{MinReconnectIntervalMs: 1000},
		closedCh:       make(chan struct{}),
		activeSessions: map[*wgSession]struct{}{},
		lastCloseAt:    time.Now(),
	}

	time.AfterFunc(10*time.Millisecond, func() {
		_ = handler.Close()
	})
	if err := handler.waitReconnectInterval(context.Background()); err == nil {
		t.Fatal("expected wait to stop with handler closed error")
	}
}

func TestWGSessionResourcesCanBeReadWhileClosing(t *testing.T) {
	session := &wgSession{tun: newFakeTunDevice()}
	done := make(chan struct{})
	ready := make(chan struct{})

	go func() {
		close(ready)
		for {
			select {
			case <-done:
				return
			default:
				_, _, _ = session.resources()
			}
		}
	}()

	<-ready
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	close(done)

	if !session.IsClosed() {
		t.Fatal("expected session to be closed")
	}
}
