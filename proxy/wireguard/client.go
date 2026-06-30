package wireguard

import (
	"context"
	"fmt"
	gonet "net"
	"net/netip"
	reflect "reflect"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"golang.zx2c4.com/wireguard/device"
)

type wgSession struct {
	tun  tun.Device
	tnet *Net
	dev  *device.Device

	mu        sync.Mutex
	closeOnce sync.Once
	closeErr  error
	closed    bool
}

func (s *wgSession) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.closed = true
		if s.dev != nil {
			s.dev.Close()
			return
		}
		if s.tun != nil {
			s.closeErr = s.tun.Close()
		}
	})
	return s.closeErr
}

func (s *wgSession) IsClosed() bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *wgSession) resources() (*device.Device, *Net, bool) {
	if s == nil {
		return nil, nil, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dev, s.tnet, s.closed
}

type Handler struct {
	conf          *DeviceConfig
	policyManager policy.Manager
	dns           dns.Client

	streamSettings  *internet.MemoryStreamConfig
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter

	persistent *wgSession

	mu             sync.Mutex
	closeOnce      sync.Once
	closed         bool
	activeSessions map[*wgSession]struct{}
	sessionLimiter chan struct{}
	closedCh       chan struct{}
	lastCloseAt    time.Time
}

func NewClient(ctx context.Context, conf *DeviceConfig) (*Handler, error) {
	v := core.MustFromContext(ctx)
	p := v.GetFeature(policy.ManagerType()).(policy.Manager)
	d := v.GetFeature(dns.ClientType()).(dns.Client)

	streamSettings := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig)
	tag := session.FullHandlerFromContext(ctx).Tag()
	var uplinkCounter stats.Counter
	var downlinkCounter stats.Counter
	if len(tag) > 0 && p.ForSystem().Stats.OutboundUplink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "outbound>>>" + tag + ">>>traffic>>>uplink"
		c, _ := stats.GetOrRegisterCounter(statsManager, name)
		if c != nil {
			uplinkCounter = c
		}
	}
	if len(tag) > 0 && p.ForSystem().Stats.OutboundDownlink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		name := "outbound>>>" + tag + ">>>traffic>>>downlink"
		c, _ := stats.GetOrRegisterCounter(statsManager, name)
		if c != nil {
			downlinkCounter = c
		}
	}

	if len(conf.Peers) == 0 {
		return nil, errors.New("empty peers")
	}
	for _, peer := range conf.Peers {
		if peer.PublicKey == "" {
			return nil, errors.New("peer without publickey")
		}
		if peer.Endpoint == "" {
			return nil, errors.New("peer without endpoint")
		}
	}
	if _, err := parseLocalAddresses(conf.Endpoint); err != nil {
		return nil, err
	}
	if conf.MinReconnectIntervalMs < 0 {
		return nil, errors.New("minReconnectIntervalMs must be greater than or equal to 0")
	}
	if conf.MaxConcurrentSessions < 0 {
		return nil, errors.New("maxConcurrentSessions must be greater than or equal to 0")
	}
	if conf.Lifecycle == DeviceConfig_PER_CONNECTION {
		if !conf.IsClient {
			return nil, errors.New("wireguard lifecycle perConnection is only supported for client outbound")
		}
		if !conf.NoKernelTun {
			return nil, errors.New("wireguard lifecycle perConnection requires noKernelTun=true")
		}
		if conf.MaxConcurrentSessions <= 0 {
			conf.MaxConcurrentSessions = 1
		}
	}

	h := &Handler{
		conf:          conf,
		policyManager: p,
		dns:           d,

		streamSettings:  streamSettings,
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,

		closedCh:       make(chan struct{}),
		activeSessions: map[*wgSession]struct{}{},
	}
	if conf.MaxConcurrentSessions > 0 {
		h.sessionLimiter = make(chan struct{}, int(conf.MaxConcurrentSessions))
	}
	if conf.Lifecycle != DeviceConfig_PER_CONNECTION {
		persistent, err := h.newSession(ctx)
		if err != nil {
			return nil, err
		}
		h.persistent = persistent
	}
	return h, nil
}

// Process implements proxy.Outbound.Process.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "wireguard"
	ob.CanSpliceCopy = 3

	if h.conf.Lifecycle == DeviceConfig_PER_CONNECTION {
		return h.processWithTemporarySession(ctx, link)
	}
	return h.processWithPersistentSession(ctx, link)
}

func (h *Handler) processWithPersistentSession(ctx context.Context, link *transport.Link) error {
	session, err := h.getPersistentSession(ctx)
	if err != nil {
		return err
	}
	if err := h.initSession(ctx, session); err != nil {
		return err
	}
	return h.processWithSession(ctx, link, session)
}

func (h *Handler) processWithTemporarySession(ctx context.Context, link *transport.Link) error {
	release, err := h.acquireSessionSlot(ctx)
	if err != nil {
		return err
	}
	defer release()

	if err := h.waitReconnectInterval(ctx); err != nil {
		return err
	}

	session, err := h.newSession(ctx)
	if err != nil {
		return err
	}
	if err := h.registerActiveSession(session); err != nil {
		_ = session.Close()
		return err
	}
	defer func() {
		h.unregisterActiveSession(session)
		_ = session.Close()
		h.markSessionClosed()
	}()

	if err := h.initSession(ctx, session); err != nil {
		return err
	}
	return h.processWithSession(ctx, link, session)
}

func (h *Handler) processWithSession(ctx context.Context, link *transport.Link, wgSession *wgSession) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	dev, tnet, closed := wgSession.resources()
	if closed || tnet == nil || dev == nil {
		return errors.New("wireguard session is not initialized")
	}

	if err := dev.Up(); err != nil {
		return err
	}

	var addr netip.Addr
	if ob.Target.Address.Family().IsDomain() {
		ip, err := h.resolveRemoteWithNet(tnet, ob.Target.Address.String())
		if err != nil {
			return errors.New("failed to resolve domain").Base(err)
		}
		addr, _ = netip.AddrFromSlice(ip)
	} else {
		addr, _ = netip.AddrFromSlice(ob.Target.Address.IP())
	}

	addrPort := netip.AddrPortFrom(addr, ob.Target.Port.Value())
	if !addrPort.IsValid() {
		return errors.New("invalid target ", ob.Target)
	}

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := h.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)

	if newCtx != nil {
		ctx = newCtx
	}

	var reader buf.Reader
	var writer buf.Writer

	switch ob.Target.Network {
	case net.Network_TCP:
		var conn net.Conn
		var err error
		if sessionPolicy.Timeouts.Handshake != 0 {
			timeoutCtx, timeoutCancel := context.WithTimeout(ctx, sessionPolicy.Timeouts.Handshake)
			conn, err = tnet.DialContextTCPAddrPort(timeoutCtx, addrPort)
			timeoutCancel()
		} else {
			conn, err = tnet.DialContextTCPAddrPort(ctx, addrPort)
		}
		if err != nil {
			return errors.New("failed to create TCP connection").Base(err)
		}
		defer conn.Close()
		reader = buf.NewReader(conn)
		writer = buf.NewWriter(conn)
	case net.Network_UDP:
		conn, err := tnet.DialUDPAddrPort(netip.AddrPort{}, addrPort)
		if err != nil {
			return errors.New("failed to create UDP connection").Base(err)
		}
		defer conn.Close()
		c := &udpConnClient{
			PacketConn: conn.(*internet.PacketConnWrapper).PacketConn,
			resolveFunc: func(host string) (net.IP, error) {
				return h.resolveRemoteWithNet(tnet, host)
			},
			dest: gonet.UDPAddrFromAddrPort(addrPort),
		}
		reader = c
		writer = c
	default:
		panic(ob.Target.Network)
	}

	requestFunc := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, writer, buf.UpdateActivity(timer))
	}

	responseFunc := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(reader, link.Writer, buf.UpdateActivity(timer))
	}

	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return errors.New("connection ends").Base(err)
	}

	return nil
}

func (h *Handler) Close() (err error) {
	var sessions []*wgSession
	h.closeOnce.Do(func() {
		h.mu.Lock()
		h.closed = true
		if h.closedCh != nil {
			close(h.closedCh)
		}
		if h.persistent != nil {
			sessions = append(sessions, h.persistent)
			h.persistent = nil
		}
		for session := range h.activeSessions {
			sessions = append(sessions, session)
		}
		h.activeSessions = map[*wgSession]struct{}{}
		h.mu.Unlock()

		var errs []error
		for _, session := range sessions {
			errs = append(errs, session.Close())
		}
		err = errors.Combine(errs...)
	})
	return err
}

func (h *Handler) getPersistentSession(ctx context.Context) (*wgSession, error) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, errors.New("wireguard handler is closed")
	}
	existing := h.persistent
	h.mu.Unlock()

	if existing != nil {
		if !existing.IsClosed() {
			return existing, nil
		}
		h.mu.Lock()
		if h.persistent == existing {
			h.persistent = nil
		}
		h.mu.Unlock()
	}

	session, err := h.newSession(ctx)
	if err != nil {
		return nil, err
	}

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		_ = session.Close()
		return nil, errors.New("wireguard handler is closed")
	}
	existing = h.persistent
	if existing == nil {
		h.persistent = session
		h.mu.Unlock()
		return session, nil
	}
	h.mu.Unlock()

	if !existing.IsClosed() {
		_ = session.Close()
		return existing, nil
	}

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		_ = session.Close()
		return nil, errors.New("wireguard handler is closed")
	}
	if h.persistent == existing {
		h.persistent = session
		h.mu.Unlock()
		return session, nil
	}
	h.mu.Unlock()
	_ = session.Close()
	return h.getPersistentSession(ctx)
}

func (h *Handler) acquireSessionSlot(ctx context.Context) (func(), error) {
	if h.sessionLimiter == nil {
		if h.isClosed() {
			return nil, errors.New("wireguard handler is closed")
		}
		return func() {}, nil
	}
	select {
	case h.sessionLimiter <- struct{}{}:
		if h.isClosed() {
			<-h.sessionLimiter
			return nil, errors.New("wireguard handler is closed")
		}
		return func() { <-h.sessionLimiter }, nil
	case <-h.closedCh:
		return nil, errors.New("wireguard handler is closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *Handler) waitReconnectInterval(ctx context.Context) error {
	interval := time.Duration(h.conf.MinReconnectIntervalMs) * time.Millisecond
	if interval <= 0 {
		return nil
	}
	h.mu.Lock()
	waitUntil := h.lastCloseAt.Add(interval)
	closedCh := h.closedCh
	h.mu.Unlock()

	wait := time.Until(waitUntil)
	if wait <= 0 {
		return nil
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-closedCh:
		return errors.New("wireguard handler is closed")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Handler) registerActiveSession(session *wgSession) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return errors.New("wireguard handler is closed")
	}
	if h.activeSessions == nil {
		h.activeSessions = map[*wgSession]struct{}{}
	}
	h.activeSessions[session] = struct{}{}
	return nil
}

func (h *Handler) unregisterActiveSession(session *wgSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.activeSessions, session)
}

func (h *Handler) markSessionClosed() {
	h.mu.Lock()
	h.lastCloseAt = time.Now()
	h.mu.Unlock()
}

func (h *Handler) isClosed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}

func parseLocalAddresses(endpoints []string) ([]netip.Addr, error) {
	localAddresses := make([]netip.Addr, 0, len(endpoints))
	for _, localaddress := range endpoints {
		addr, err := netip.ParseAddr(localaddress)
		if err == nil {
			localAddresses = append(localAddresses, addr)
			continue
		}
		prefix, err := netip.ParsePrefix(localaddress)
		if err == nil {
			localAddresses = append(localAddresses, prefix.Addr())
			continue
		}
		return nil, err
	}
	return localAddresses, nil
}

func (h *Handler) newSession(ctx context.Context) (*wgSession, error) {
	localAddresses, err := parseLocalAddresses(h.conf.Endpoint)
	if err != nil {
		return nil, err
	}

	kernelTunSupported, err := KernelTunSupported()
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "Failed to check kernel TUN support")
	}
	var tunDevice tun.Device
	var tnet *Net
	if !h.conf.NoKernelTun && kernelTunSupported {
		errors.LogWarning(context.Background(), "Using kernel TUN")
		tunDevice, tnet, err = createKernelTun(localAddresses, []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1"), netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("2606:4700:4700::1001")}, int(h.conf.Mtu))
	} else {
		errors.LogWarning(context.Background(), "Using gVisor TUN")
		tunDevice, tnet, _, err = CreateNetTUN(localAddresses, []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1"), netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("2606:4700:4700::1001")}, int(h.conf.Mtu), true)
	}
	if err != nil {
		return nil, err
	}
	return &wgSession{tun: tunDevice, tnet: tnet}, nil
}

func (h *Handler) initSession(ctx context.Context, session *wgSession) error {
	if session == nil {
		return errors.New("wireguard session is nil")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if h.isClosed() {
		return errors.New("wireguard handler is closed")
	}
	if session.closed {
		return errors.New("wireguard session is closed")
	}
	if session.dev != nil {
		return nil
	}
	if session.tun == nil {
		return errors.New("wireguard session is closed")
	}
	resolveFunc := h.resolveLocal
	listenFunc := func() (net.PacketConn, error) {
		dest, err := net.ParseDestination("udp:" + h.conf.Peers[0].Endpoint)
		if err != nil {
			return nil, err
		}
		conn, err := internet.DialSystem(ctx, dest, h.streamSettings.SocketSettings)
		if err != nil {
			return nil, err
		}
		var pktConn net.PacketConn
		switch c := conn.(type) {
		case *internet.PacketConnWrapper:
			pktConn = c.PacketConn
		case *cnc.Connection:
			pktConn = &internet.FakePacketConn{Conn: c}
		default:
			panic(reflect.TypeOf(c))
		}
		if h.streamSettings.UdpmaskManager != nil {
			newConn, err := h.streamSettings.UdpmaskManager.WrapPacketConnClient(pktConn)
			if err != nil {
				pktConn.Close()
				return nil, errors.New("mask err").Base(err)
			}
			pktConn = newConn
		}
		if h.uplinkCounter != nil || h.downlinkCounter != nil {
			pktConn = &PacketCounterConnection{
				PacketConn:   pktConn,
				ReadCounter:  h.downlinkCounter,
				WriteCounter: h.uplinkCounter,
			}
		}
		return pktConn, nil
	}
	bind := &bind{}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Debug,
				Content:  fmt.Sprintf(format, args...),
			})
		},
		Errorf: func(format string, args ...any) {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Error,
				Content:  fmt.Sprintf(format, args...),
			})
		},
	}
	dev := device.NewDevice(session.tun, bind, logger)
	closeFailedDevice := func() {
		dev.Close()
		session.closed = true
		session.dev = nil
		session.tun = nil
		session.tnet = nil
	}
	bind.resolveFunc = resolveFunc
	bind.listenFunc = listenFunc
	bind.downFunc = dev.Down
	bind.reserved = h.conf.Reserved
	var cfg strings.Builder
	cfg.WriteString("private_key=" + h.conf.SecretKey + "\n")
	for _, peer := range h.conf.Peers {
		cfg.WriteString("public_key=" + peer.PublicKey + "\n")
		if peer.PreSharedKey != "" {
			cfg.WriteString("preshared_key=" + peer.PreSharedKey + "\n")
		}
		cfg.WriteString("endpoint=" + peer.Endpoint + "\n")
		for _, ip := range peer.AllowedIps {
			cfg.WriteString("allowed_ip=" + ip + "\n")
		}
		if peer.KeepAlive != "" {
			cfg.WriteString("persistent_keepalive_interval=" + peer.KeepAlive + "\n")
		}
	}
	err := dev.IpcSet(cfg.String())
	if err != nil {
		closeFailedDevice()
		return err
	}
	err = dev.Up()
	if err != nil {
		closeFailedDevice()
		return err
	}
	session.dev = dev
	return nil
}

func (h *Handler) resolveLocal(host string) (net.IP, error) {
	return resolveDomain(host, h.conf.DomainStrategy, func(host string) ([]net.IP, error) {
		ips, _, err := h.dns.LookupIP(host, dns.IPOption{IPv4Enable: true, IPv6Enable: true})
		return ips, err
	})
}

func (h *Handler) resolveRemote(session *wgSession, host string) (net.IP, error) {
	_, tnet, closed := session.resources()
	if closed || tnet == nil {
		return nil, errors.New("wireguard session is closed")
	}
	return h.resolveRemoteWithNet(tnet, host)
}

func (h *Handler) resolveRemoteWithNet(tnet *Net, host string) (net.IP, error) {
	return resolveDomain(host, h.conf.DomainStrategy, func(host string) ([]net.IP, error) {
		addrs, err := tnet.LookupHost(host)
		if err != nil {
			return nil, err
		}
		ips := make([]net.IP, 0, len(addrs))
		for _, addr := range addrs {
			ips = append(ips, net.ParseIP(addr))
		}
		return ips, nil
	})
}

func resolveDomain(host string, strategy DeviceConfig_DomainStrategy, lookupIP func(host string) ([]net.IP, error)) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	ips, err := lookupIP(host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, dns.ErrEmptyResponse
	}
	var got4, got6 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			got4 = append(got4, ip)
		} else {
			got6 = append(got6, ip)
		}
	}
	var got []net.IP
	switch strategy {
	case DeviceConfig_FORCE_IP:
		got = ips
		return ips[dice.Roll(len(ips))], nil
	case DeviceConfig_FORCE_IP4:
		got = got4
	case DeviceConfig_FORCE_IP6:
		got = got6
	case DeviceConfig_FORCE_IP46:
		got = got4
		if len(got) == 0 {
			got = got6
		}
	case DeviceConfig_FORCE_IP64:
		got = got6
		if len(got) == 0 {
			got = got4
		}
	default:
		panic(strategy)
	}
	if len(got) == 0 {
		return nil, dns.ErrEmptyResponse
	}
	return got[dice.Roll(len(got))], nil
}

type udpConnClient struct {
	net.PacketConn
	resolveFunc func(host string) (net.IP, error)
	dest        *net.UDPAddr
}

func (c *udpConnClient) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Resize(0, buf.Size)
	n, addr, err := c.PacketConn.ReadFrom(b.Bytes())
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Resize(0, int32(n))

	b.UDP = &net.Destination{
		Address: net.IPAddress(addr.(*net.UDPAddr).IP),
		Port:    net.Port(addr.(*net.UDPAddr).Port),
		Network: net.Network_UDP,
	}

	return buf.MultiBuffer{b}, nil
}

func (c *udpConnClient) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, b := range mb {
		dst := c.dest
		if b.UDP != nil {
			if b.UDP.Address.Family().IsDomain() {
				ip, err := c.resolveFunc(b.UDP.Address.String())
				if err != nil {
					errors.LogErrorInner(context.Background(), err, "drop packet to ", b.UDP, " with size ", len(b.Bytes()))
					b.Release()
					continue
				}
				dst = &net.UDPAddr{
					IP:   ip,
					Port: int(b.UDP.Port),
				}
			} else {
				dst = b.UDP.RawNetAddr().(*net.UDPAddr)
			}
		}
		_, err := c.PacketConn.WriteTo(b.Bytes(), dst)
		if err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		b.Release()
	}
	return nil
}

type PacketCounterConnection struct {
	net.PacketConn
	ReadCounter  stats.Counter
	WriteCounter stats.Counter
}

func (c *PacketCounterConnection) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.PacketConn.ReadFrom(p)
	if err == nil && c.ReadCounter != nil {
		c.ReadCounter.Add(int64(n))
	}
	return
}

func (c *PacketCounterConnection) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = c.PacketConn.WriteTo(p, addr)
	if err == nil && c.WriteCounter != nil {
		c.WriteCounter.Add(int64(n))
	}
	return
}
