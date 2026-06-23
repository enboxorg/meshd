package engine

import "net/netip"

func tunnelRoutes(routes, localRoutes []netip.Prefix) []netip.Prefix {
	localRouteSet := make(map[netip.Prefix]bool, len(localRoutes))
	for _, lr := range localRoutes {
		localRouteSet[lr] = true
	}

	tunnel := make([]netip.Prefix, 0, len(routes))
	for _, rt := range routes {
		if !localRouteSet[rt] {
			tunnel = append(tunnel, rt)
		}
	}
	return tunnel
}
