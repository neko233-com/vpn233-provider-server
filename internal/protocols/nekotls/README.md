## NekoTLS 协议策略

该目录维护 `NekoTLS` 的策略实现与互操作性约束，包含三类产物：

- sing-box 服务端入站模板（内部使用 `anytls`）
- mihomo/fork 客户端 `type: nekotls` 映射
- 订阅/链接层的渲染与配置验证

兼容说明：

- 领域名模式（domain）：走 ECH + `skip-cert-verify: false`，`ech-opts.enable=true`
- 无域名模式（IP）：走 Reality fallback，`reality-opts` 替代 ECH

`provider` 端在标准 clash/clash-meta 订阅目标时，会自动回退为 `anytls`，保持旧客户端兼容。旗舰目标 `clash-meta-nekotls` 保留 `type: nekotls`。
