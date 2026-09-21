// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"net"
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/envknob"
	"tailscale.com/tstest"
)

func TestEndpointExclusion(t *testing.T) {
	mk := func(name string, addrs ...string) Interface {
		i := Interface{Interface: &net.Interface{Name: name, Flags: net.FlagUp}}
		for _, a := range addrs {
			ip, network, err := net.ParseCIDR(a)
			if err != nil {
				t.Fatal(err)
			}
			network.IP = ip
			i.AltAddrs = append(i.AltAddrs, network)
		}
		return i
	}
	tstest.Replace(t, &altNetInterfaces, func() ([]Interface, error) {
		return []Interface{
			mk("eth0", "192.0.2.1/24", "2001:db8:1::1/64"),
			mk("cilium_host", "192.0.2.2/24", "2001:db8:2::1/64"),
			mk("lo", "127.0.0.1/8", "::1/128"),
			mk("zt0", "192.0.2.3/24"),
		}, nil
	})
	for _, tt := range []struct {
		name, avoid, only, prefix string
		want                      []string
		loop                      []string
	}{
		{name: "baseline", want: []string{"192.0.2.1", "192.0.2.2", "2001:db8:1::1", "2001:db8:2::1"}, loop: []string{"127.0.0.1", "::1"}},
		{name: "avoid glob whitespace", avoid: " , cilium* , [ ,", want: []string{"192.0.2.1", "2001:db8:1::1"}, loop: []string{"127.0.0.1", "::1"}},
		{name: "only glob", only: " , eth? , ", want: []string{"192.0.2.1", "2001:db8:1::1"}},
		{name: "avoid wins", only: "*", avoid: "*"},
		{name: "prefix v4 v6", prefix: "bad, 192.0.2.2/32, 2001:db8:2::/64, ", want: []string{"192.0.2.1", "2001:db8:1::1"}, loop: []string{"127.0.0.1", "::1"}},
		{name: "all addresses excluded", prefix: "0.0.0.0/0, ::/0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range map[string]string{"TS_AVOID_INTERFACES": tt.avoid, "TS_ONLY_INTERFACES": tt.only, "TS_AVOID_PREFIX": tt.prefix} {
				envknob.Setenv(k, v)
				t.Cleanup(func() { envknob.Setenv(k, "") })
			}
			regular, loop, err := LocalAddresses()
			if err != nil {
				t.Fatal(err)
			}
			parse := func(ss []string) (out []netip.Addr) {
				for _, s := range ss {
					out = append(out, netip.MustParseAddr(s))
				}
				return
			}
			if !reflect.DeepEqual(regular, parse(tt.want)) || !reflect.DeepEqual(loop, parse(tt.loop)) {
				t.Fatalf("regular=%v loop=%v", regular, loop)
			}
		})
	}
}
