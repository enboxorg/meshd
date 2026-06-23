package engine

import (
	"net/netip"
	"strings"
)

func darwinAddrFamily(p netip.Prefix) string {
	if p.Addr().Is6() {
		return "inet6"
	}
	return "inet"
}

func darwinAddrAddArgs(tunName string, addr netip.Prefix) []string {
	return []string{"ifconfig", tunName, darwinAddrFamily(addr), addr.String(), addr.Addr().String()}
}

func darwinAddrDeleteArgs(tunName string, addr netip.Prefix) []string {
	return []string{"ifconfig", tunName, darwinAddrFamily(addr), addr.String(), "-alias"}
}

func darwinRouteAddArgs(tunName string, route netip.Prefix) []string {
	return darwinRouteArgs("add", tunName, route)
}

func darwinRouteDeleteArgs(tunName string, route netip.Prefix) []string {
	return darwinRouteArgs("delete", tunName, route)
}

func darwinRouteArgs(action string, tunName string, route netip.Prefix) []string {
	return []string{
		"route", "-q", "-n",
		action, "-" + darwinAddrFamily(route), route.Masked().String(),
		"-iface", tunName,
	}
}

func commandAlreadyExists(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "file exists") ||
		strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "already in use")
}

func commandAlreadyGone(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not in table") ||
		strings.Contains(msg, "no such process") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "can't assign requested address")
}
