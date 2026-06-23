package engine

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func TestTunnelRoutesExcludesLocalRoutes(t *testing.T) {
	peer := netip.MustParsePrefix("10.200.0.2/32")
	local := netip.MustParsePrefix("192.168.1.0/24")
	got := tunnelRoutes([]netip.Prefix{peer, local}, []netip.Prefix{local})
	want := []netip.Prefix{peer}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tunnelRoutes() = %v, want %v", got, want)
	}
}

func TestDarwinRouteArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "ipv4 add",
			args: darwinRouteAddArgs("utun7", netip.MustParsePrefix("10.200.0.2/32")),
			want: []string{"route", "-q", "-n", "add", "-inet", "10.200.0.2/32", "-iface", "utun7"},
		},
		{
			name: "ipv6 delete",
			args: darwinRouteDeleteArgs("utun7", netip.MustParsePrefix("fd7a:115c:a1e0::1/128")),
			want: []string{"route", "-q", "-n", "delete", "-inet6", "fd7a:115c:a1e0::1/128", "-iface", "utun7"},
		},
	}

	for _, tt := range tests {
		if !reflect.DeepEqual(tt.args, tt.want) {
			t.Fatalf("%s args = %v, want %v", tt.name, tt.args, tt.want)
		}
	}
}

func TestDarwinAddressArgs(t *testing.T) {
	addr := netip.MustParsePrefix("10.200.0.1/32")
	addWant := []string{"ifconfig", "utun7", "inet", "10.200.0.1/32", "10.200.0.1"}
	delWant := []string{"ifconfig", "utun7", "inet", "10.200.0.1/32", "-alias"}

	if got := darwinAddrAddArgs("utun7", addr); !reflect.DeepEqual(got, addWant) {
		t.Fatalf("darwinAddrAddArgs() = %v, want %v", got, addWant)
	}
	if got := darwinAddrDeleteArgs("utun7", addr); !reflect.DeepEqual(got, delWant) {
		t.Fatalf("darwinAddrDeleteArgs() = %v, want %v", got, delWant)
	}
}

func TestCommandErrorClassifiers(t *testing.T) {
	if !commandAlreadyExists(errors.New("route: writing to routing socket: File exists")) {
		t.Fatal("expected File exists to be classified as already exists")
	}
	if !commandAlreadyGone(errors.New("route: writing to routing socket: not in table")) {
		t.Fatal("expected not in table to be classified as already gone")
	}
	if commandAlreadyGone(errors.New("permission denied")) {
		t.Fatal("did not expect permission denied to be classified as already gone")
	}
}
