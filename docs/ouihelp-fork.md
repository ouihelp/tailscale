# Ouihelp fork patches

This fork targets new Linux clusters on upstream Tailscale v1.102.4.
It carries three narrowly scoped patches, not a general Cilium integration.
No migration guarantee is implied.

## 1. Fixed firewall mark allocation

The fork ports the existing Ouihelp allocation: mask `0xf000`,
subnet mark `0x1000`, and bypass mark `0x2000`.
This keeps Tailscale marks in the intended bit range for coexistence
with the surrounding network stack; other mark users must still be audited.
iptables, nftables, routing expectations and regression tests agree
on that allocation. Upstream v1.102.4 native-endian handling is preserved.

[Upstream PR #18695](https://github.com/tailscale/tailscale/pull/18695)
is an open, unmerged configurable-marks proposal: a related solution,
not a wholesale backport. This fork's marks are fixed, not configurable.
