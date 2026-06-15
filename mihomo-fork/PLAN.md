# mihomo fork plan — native `type: nekotls`

> Goal: give Clash.Meta / mihomo a **native** outbound proxy type `nekotls` so a
> `clash-meta-nekotls` subscription loads and dials without any external bridge.
> This is the one step that cannot be avoided if we want *native* Clash support
> (stock mihomo cannot parse an unknown `type:`).

The provider repo (`vpn233-provider-server`) is the **source of truth** for the
NekoTLS wire model and config schema. This fork only has to:

1. recognise `type: nekotls` in the config parser, and
2. implement the outbound dialer by composing primitives mihomo already ships.

## 1. What NekoTLS is (recap)

NekoTLS = an **AnyTLS-compatible outer stream over TLS 1.3** plus a camouflage
layer that no upstream core exposes as a single composite:

| Layer                | Source primitive in mihomo            |
| -------------------- | ------------------------------------- |
| Stream / muxing      | `transport/anytls` (+ padding scheme) |
| uTLS ClientHello     | `component/tls` fingerprint utils     |
| ECH (domain mode)    | `component/ech`                       |
| Reality (no-domain)  | `transport/reality`                   |
| Auth                 | password (blake3-derived session key) |

Server side is **already deployable on stock sing-box** via its native `anytls`
inbound (see `vpn233-provider-server` → `singBoxNekoTLSInbound`). The fork is a
**client/outbound-only** change.

## 2. Fork the right repo

```bash
# upstream
git clone https://github.com/MetaCubeX/mihomo.git mihomo-nekotls
cd mihomo-nekotls
git remote rename origin upstream
git checkout -b feat/nekotls
```

Pin to a release tag you ship against (match the provider install script default,
currently `v1.18.9`+):

```bash
git checkout -b feat/nekotls vX.Y.Z
```

## 3. Files to add / touch

```
adapter/
  outbound/
    nekotls.go        # NEW — the C.ProxyAdapter implementation
  parser.go           # EDIT — add `case "nekotls":` to ParseProxy
constant/
  adapter.go          # EDIT — add `NekoTLS` to the AdapterType enum + String()
docs/
  configuration/...   # EDIT — document the proxy fields
```

Reference skeletons live next to this plan:

- [adapter/outbound_nekotls.go.txt](adapter/outbound_nekotls.go.txt) → copy to `adapter/outbound/nekotls.go`
- [adapter/parser_nekotls.go.txt](adapter/parser_nekotls.go.txt) → merge into `adapter/parser.go`

## 4. Config schema (the contract)

The option struct mirrors `NekoTLSOption` in
[../nekotls.go](../nekotls.go) one-to-one. mihomo decodes the YAML proxy
mapping into this struct with its `structure` package, so the field **`proxy:`
tags must match** the YAML keys the provider emits:

```go
type NekoTLSOption struct {
    BasicOption
    Name              string            `proxy:"name"`
    Server            string            `proxy:"server"`
    Port              int               `proxy:"port"`
    Password          string            `proxy:"password"`
    UDP               bool              `proxy:"udp,omitempty"`
    SNI               string            `proxy:"sni,omitempty"`
    ALPN              []string          `proxy:"alpn,omitempty"`
    ClientFingerprint string            `proxy:"client-fingerprint,omitempty"`
    PaddingScheme     string            `proxy:"padding-scheme,omitempty"`
    SkipCertVerify    bool              `proxy:"skip-cert-verify,omitempty"`
    ECHOpts           *NekoTLSECH       `proxy:"ech-opts,omitempty"`
    RealityOpts       *NekoTLSReality   `proxy:"reality-opts,omitempty"`
}
type NekoTLSECH struct {
    Enable bool   `proxy:"enable"`
    Config string `proxy:"config"`
}
type NekoTLSReality struct {
    PublicKey string `proxy:"public-key"`
    ShortID   string `proxy:"short-id"`
}
```

**Invariants** (enforced by `NekoTLSOption.Validate()` in the provider, and
re-checked here): exactly one of `ech-opts.enable=true` or `reality-opts`; ECH
requires a non-empty `config`; Reality requires `public-key` + `short-id`.

The provider ships `DecodeNekoTLSOption(map[string]any)` which is byte-for-byte
the loader contract — CI in the provider repo decodes every generated proxy
through it, so a green provider build guarantees this fork can load the output.

## 5. Dial composition

```
NewNekoTLS(option):
    tlsConfig = base TLS (serverName=SNI, alpn=ALPN, insecure=SkipCertVerify)
    fingerprint = option.ClientFingerprint (default "chrome")
    if option.ECHOpts.Enable:
        tlsConfig.ECHConfig = base64decode(option.ECHOpts.Config)   # component/ech
    else: # reality
        realityCfg = reality.Config{PublicKey, ShortID, fingerprint}
    anytlsClient = anytls.NewClient(password, paddingScheme)
    DialContext = anytlsClient.DialContext over (reality|utls+ech) conn
```

All four building blocks already exist in mihomo; NekoTLS is the glue + the
single `type:` keyword.

## 6. Build & release

```bash
go run ./test/... || true
make WITH_GVISOR=1            # or: go build -tags with_gvisor ./...
# smoke-load a provider-generated subscription:
./mihomo -t -d . -f ./mihomo-fork/config-examples/clash-meta-nekotls.example.yaml
```

`mihomo -t` runs config validation only; it must parse `type: nekotls` and
return exit 0. Wire this into the provider's `scripts/verify.*` once a fork
binary is published (`VPN233_MIHOMO_FORK_BIN`).

## 7. Compatibility / fallback

- `clash` / `clash-meta` subscribe targets keep emitting `type: anytls`
  (the provider substitutes nekotls→anytls), so **stock** cores stay supported.
- Only `clash-meta-nekotls` emits `type: nekotls`, served by this fork.
- sing-box clients consume the `sing-box` target (native `anytls` inbound).

## 8. Upstreaming

If MetaCubeX accepts it, propose `nekotls` as a thin composite of
`anytls + ech + reality + utls`. Until then, keep `feat/nekotls` rebased on
upstream tags and publish fork binaries under the vpn233 release channel.
