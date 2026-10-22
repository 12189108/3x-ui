package network

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type unixPeerKey struct{}

// ConnContext marks Unix sockets from the actual connection, never from headers.
func ClientIPConnContext(ctx context.Context, conn net.Conn) context.Context {
	return context.WithValue(ctx, unixPeerKey{}, conn.RemoteAddr().Network() == "unix")
}

type ClientIPResolver struct{ trusted []netip.Prefix }

func NewClientIPResolver(extra string) (*ClientIPResolver, error) {
	r := &ClientIPResolver{trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}}
	for _, value := range strings.Split(extra, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			ip, parseErr := netip.ParseAddr(value)
			if parseErr != nil {
				return nil, errors.New("invalid XUI_TRUSTED_PROXIES entry")
			}
			ip = ip.Unmap()
			prefix = netip.PrefixFrom(ip, ip.BitLen())
		}
		if prefix.Bits() == 0 {
			return nil, errors.New("trusting every proxy address is not allowed")
		}
		r.trusted = append(r.trusted, prefix)
	}
	return r, nil
}

func parseClientIP(value string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || ip.IsUnspecified() {
		return netip.Addr{}, errors.New("invalid client IP")
	}
	return ip.WithZone("").Unmap(), nil
}

func (r *ClientIPResolver) trustedPeer(ip netip.Addr) bool {
	for _, prefix := range r.trusted {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (r *ClientIPResolver) Resolve(req *http.Request) (netip.Addr, error) {
	unixPeer, _ := req.Context().Value(unixPeerKey{}).(bool)
	var peer netip.Addr
	if !unixPeer {
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			return netip.Addr{}, errors.New("invalid connection address")
		}
		peer, err = parseClientIP(host)
		if err != nil {
			return netip.Addr{}, err
		}
		if !r.trustedPeer(peer) {
			return peer, nil
		}
	}
	// Nginx overwrites X-Raw-Ip with its connection/PROXY-protocol source.
	// It takes precedence over X-Real-IP, which may contain client-supplied XFF.
	if value := req.Header.Get("X-Raw-Ip"); value != "" {
		return parseClientIP(value)
	}
	if value := req.Header.Get("X-Forwarded-For"); value != "" {
		if len(value) > 4096 {
			return netip.Addr{}, errors.New("forwarded IP chain too long")
		}
		parts := strings.Split(value, ",")
		if len(parts) > 32 {
			return netip.Addr{}, errors.New("forwarded IP chain too long")
		}
		ips := make([]netip.Addr, len(parts))
		for i, part := range parts {
			var err error
			ips[i], err = parseClientIP(part)
			if err != nil {
				return netip.Addr{}, err
			}
		}
		for i := len(ips) - 1; i >= 0; i-- {
			if i == 0 || !r.trustedPeer(ips[i]) {
				return ips[i], nil
			}
		}
	}
	if value := req.Header.Get("X-Real-IP"); value != "" {
		return parseClientIP(value)
	}
	if unixPeer {
		return netip.Addr{}, errors.New("Unix proxy must provide a client IP header")
	}
	return peer, nil
}
