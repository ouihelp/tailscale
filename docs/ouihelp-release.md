# Ouihelp 1.102.4-ouihelp.1 candidate

Base: upstream stable tag `v1.102.4`, not main. Embedded short version remains
`1.102.4` for infrastructure compatibility; long version and Go build metadata
identify the exact fork commit. The archive/tag version is `1.102.4-ouihelp.1`.

## Patch provenance

1. Port of `v1.96.4-ouihelp.1` firewall allocation: mask `0xf000`, subnet
   `0x1000`, bypass `0x2000`. Constants feed routing, sockets, iptables and
   nftables/conntrack. Retains v1.102.4's native-endian nftables encoding and
   conditional connmark restore (not the old hard-coded byte arrays).
2. Backport of tailscale/tailscale PR #17762, head
   `679002272decccca48cb03a58fc7721835ee058d`: 72 added lines in
   `net/netmon/state.go`, plus local endpoint-exclusion regression tests.
3. Local opt-out for the global src_valid_mark write, with bounded diagnostics
   and tests. Neither PR #18695 nor draft PR #19860 is integrated.

## Daemon environment

- `TS_AVOID_INTERFACES=cilium*` excludes matching interfaces from local endpoint
  gathering, for both IPv4 and IPv6. This is not a firewall/drop rule and does
  not change routes, STUN public endpoints, or peers' advertised addresses.
- `TS_ONLY_INTERFACES` restricts gathering to a comma-separated allowlist;
  `TS_AVOID_INTERFACES` takes precedence. Both accept Go `path.Match` globs,
  trim surrounding whitespace, and ignore empty/invalid patterns. An explicitly
  nonempty only-list with no valid matches excludes everything.
- `TS_AVOID_PREFIX` excludes comma-separated IPv4/IPv6 CIDRs from local endpoint
  gathering. Whitespace is trimmed; malformed prefixes are ignored. Exclusion
  occurs before loopback/link-local/ULA fallback classification.
- `TS_DISABLE_SRC_VALID_MARK=true` prevents tailscaled's connmark setup from
  writing `net.ipv4.conf.all.src_valid_mark=1`. Unset or false preserves the
  upstream write and failure logging. It does **not** write zero, change any
  rp_filter value, undo a previous daemon's sysctl write, disable connmark rules,
  or change per-interface src_valid_mark. Set it in the daemon environment before
  startup; it is not a CLI preference.

With the opt-out, diagnostics run once per router lifetime when connmark setup
is enabled, not on every configuration update. They warn if any interface has
strict effective rp_filter, computed as **max(all, interface)**. `default` is
only the template for new interfaces and is never treated as a global override.
Read/parse failures produce a bounded warning rather than a false assurance.
Diagnostics are a snapshot, not continuous monitoring; later interfaces/sysctl
changes require administrator checks. Only the first read error is logged.

The intended deployment uses disabled/loose RPF, not strict RPF. Unit tests cover
all combinations of modes 0 (disabled), 1 (strict), and 2 (loose); live loose-mode
traffic validation is a separate release gate owned by the deployment operator.
Strict RPF may require a full routing/RPF fix. This is **not a universal fix**.
In particular the upstream nftables connmark implementation can overwrite
non-Tailscale mark bits; the relocation/opt-out does not redesign that behavior.

Before rollout, verify all and per-interface src_valid_mark are already zero
where required. The six reported test nodes have all rp_filter=0, Cilium/veth=0,
network/tailscale0=2, and all/per-interface src_valid_mark=0. Do not infer that
other nodes match these values. Restart with the two chosen environment knobs,
then verify sysctls stayed unchanged, local Cilium endpoints disappeared and
real bidirectional traffic still works for each firewall backend in use.

## Build and exact-artifact publication

Run from a clean committed tree:

```sh
bash scripts/ouihelp-release-candidate.sh /tmp/tailscale-release-20260921/artifacts
./tool/go test ./net/netmon ./util/linuxfw ./wgengine/router/osrouter ./tsconst
./tool/go test -race ./net/netmon ./util/linuxfw ./wgengine/router/osrouter
```

Uses the project's pinned `tool/go` through `build_dist.sh` (Go 1.26.6), static
CGO-disabled Linux amd64/arm64 binaries with unstripped upstream defaults.
`TS_VERSION_OVERRIDE=1.102.4` avoids needing a release tag. The script requires
stable-tag ancestry and a clean tree, validates embedded source metadata, runs
amd64 version commands, and generates archive/binary SHA256 manifests.
Arm64 binaries require separate native or emulated runtime validation.
Archive layout remains `tailscale-<version>-linux-<arch>/{tailscale,tailscaled}`,
with README and Go metadata alongside the binaries.

### Workflow audit

The old custom tag's `.github/workflows/ouihelp-release.yml` rebuilds on tag push,
uses setup-go instead of the pinned Tailscale toolchain, hard-codes 1.96.4, and
uploads using `--clobber`. It cannot guarantee publication of tested bytes.
It is deliberately **not carried onto this stable-based candidate**. Do not
restore/dispatch that old workflow or rebuild after testing. This candidate has
no Ouihelp tag-triggered publisher. Review repository-level workflows before
pushing a release tag; publication is an explicit operator action below.

After both architectures pass the operator's live release gate:

1. Preserve the candidate directory, hashes, test logs and exact commit in a
   durable location. Check `sha256sum -c SHA256SUMS` and
   `sha256sum -c BINARY-SHA256SUMS` in that directory.
2. Push the reviewed branch and create/push annotated tag
   `v1.102.4-ouihelp.1` at **the BUILD-METADATA Source commit**, never a newer
   documentation/merge commit. No tag is necessary for candidate building.
3. `gh release create v1.102.4-ouihelp.1 --repo ouihelp/tailscale --verify-tag
   --draft --title v1.102.4-ouihelp.1 --notes-file <approved-notes>`.
4. Upload the existing two `.tar.gz` files, `SHA256SUMS`, `BINARY-SHA256SUMS`,
   `BUILD-METADATA.txt` and `VERSION-amd64.txt` with `gh release upload`, without
   `--clobber`. Download draft assets to a fresh directory and verify hashes.
   Binary hashes can be verified after extracting the archives.
5. Publish the draft only after parent approval. Never let CI substitute rebuilt
   archives, even from the same tag. Record the tested hashes in release notes.

Rollback to `v1.96.4-ouihelp.1` retains the same mark allocation but loses both
new knobs: the old binary ignores them. That specific old version does not
contain the global src_valid_mark write; do not confuse it with stock 1.98+
binaries. A binary downgrade alone still does not undo sysctl changes made by
other processes or restore previous conntrack state. Use the operator's explicit
sysctl/environment rollback procedure, preserve node state, and recheck traffic.
Do not fall back to unpatched upstream binaries on Cilium nodes without
evaluating the different marks.
