## 协议策略目录

该目录用于承载服务端/客户端两端的协议策略实现。

当前实现里，NekoTLS 已按策略化拆分到独立目录 `internal/protocols/nekotls`，通过主流程中的策略路由挂接：

- `protocolStrategies["singbox-nekotls"]`：sing-box 下沉 `anytls` 入站（兼容现有 sing-box）
- `protocolStrategies["mihomo-nekotls"]`：mihomo/fork 客户端 `type: nekotls`

新增协议建议按如下结构建立：

- `internal/protocols/<协议名>/`
  - 共享上下文/参数结构
  - 与核心策略相关的构建器（sing-box / mihomo / link / subscribe）
  - 入参校验与降级策略

这样可以做到：

- 每个协议独立开发、独立回归
- 核心编排代码不再直接耦合每一种实现细节
- 需要兼容的 `type` 可以放在协议目录内统一维护
