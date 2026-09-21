// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsconst

// Linux firewall constants used by Tailscale.

// The following bits are added to packet marks for Tailscale use.
//
// Ouihelp patch: use marks that avoid 0x80000, which can collide with
// Cilium identity-derived marks and accidentally bypass Tailscale.
//
// We still leave the lower byte alone on the assumption that sysadmins
// commonly use those bits, and consume the upper nibble of the lower
// 16-bit mark space.
//
// The constants are in the iptables/iproute2 string format for
// matching and setting the bits, so they can be directly embedded in
// commands.
const (
	// The mask for reading/writing the 'firewall mask' bits on a packet.
	// See the comment on the const block on why we use bits 12:15.
	LinuxFwmarkMask    = "0xf000"
	LinuxFwmarkMaskNum = 0xf000

	// Packet is from Tailscale and to a subnet route destination, so
	// is allowed to be routed through this machine.
	LinuxSubnetRouteMark    = "0x1000"
	LinuxSubnetRouteMarkNum = 0x1000

	// Packet was originated by tailscaled itself, and must not be
	// routed over the Tailscale network.
	LinuxBypassMark    = "0x2000"
	LinuxBypassMarkNum = 0x2000
)
