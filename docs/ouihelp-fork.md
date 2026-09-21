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

## 2. Local endpoint filters

[Upstream PR #17762](https://github.com/tailscale/tailscale/pull/17762)
is open and unmerged. The filter implementation is taken from its exact
source head `679002272decccca48cb03a58fc7721835ee058d`.
Local IPv4 and IPv6 regression tests are retained alongside the backport.

Use `TS_AVOID_INTERFACES=cilium*` to omit matching interfaces when gathering
local endpoints. The patch also supports the upstream address filtering.
This only filters local endpoint gathering, not all learned peer endpoints,
routes or STUN results. It is not a guaranteed migration fix and does not
replace routing or firewall policy. Defaults remain unchanged when unset.

## 3. Opt out of the global src_valid_mark write

Set `TS_DISABLE_SRC_VALID_MARK=true` to prevent Tailscale's new global
`src_valid_mark` write. This is opt-in; default upstream behavior is unchanged.
The switch never resets existing sysctls, `rp_filter`, or connmark state.
Existing host settings therefore still require independent verification.

A one-time diagnostic checks effective strict reverse-path filtering using
`max(all, interface)`. This is diagnostic only, not a claim of universal
strict-RPF compatibility; routing and mark interactions remain host-specific.

[Upstream issue #19796](https://github.com/tailscale/tailscale/issues/19796)
is open. [PR #19860](https://github.com/tailscale/tailscale/pull/19860)
is open and draft, proposes a different, broader routing approach, and is
**not incorporated** in this fork.

The intended new-cluster environment combines `TS_AVOID_INTERFACES=cilium*`
with `TS_DISABLE_SRC_VALID_MARK=true`. Existing clusters are outside this
patch set's migration scope. Focused unit tests cover the opt-out and diagnostic;
privileged kernel behavior requires separate native host validation.
