# tcpm SocketPuller 并发竞态修复验证

## Bug 描述
`TcpM_Works`（工作线程）对 `m->Puller`（`SocketPuller`）的访问原本**未加锁**：
- `p->Select(p, ...)` 读取 fd_set / 内部 BST
- `p->Del(p, s); p->Add(p, s, ...)` 修改 fd_set / BST
- `m->Agents[Ctx.ServerIndex]->Add(...)` 修改各上游 puller

而 `TcpM_Send`（前端线程，经 `MMgr_Send`）已在 `m->Lock` 保护下通过
`TcpM_Send_Actual` 修改同一 `m->Puller`（`m->Puller.Add`，tcpm.c:545）和
`m->Agents[]`（`TcpM_Connect_Recycle`）。

`SocketPuller` 在 `socketpuller.h` 中明确标注为 **non-thread-safe**。两个线程
无锁并发读写同一 `SocketPuller` 的 `fd_set` 与 BST 节点，构成数据竞争，可能
破坏 fd_set 位图或 BST 结构，导致 select 扫到错位 fd、BST 查找命中错误节点、
节点丢失或 double-free，表现为偶发丢查询、断言失败或崩溃。

## 修复
在 `TcpM_Works` 中每一处对 `m->Puller` / `m->Agents[]` 的 `Select` / `Del` /
`Add` 访问前后，用 `EFFECTIVE_LOCK_GET/RELEASE(m->Lock)` 包裹，使其与
`TcpM_Send` 链（已在 `m->Lock` 下访问同一 puller）对称地串行化。

加锁采用「瞬时加锁-操作-释放」模式：
- `Select` 仅在调用瞬间持锁，不长时间阻塞 `TcpM_Send`；
- 调用 `TcpM_Send_Actual`（其内部自行加锁）时**不**持有 `m->Lock`，避免锁重入；
- 拷贝 `TcpCtx` 与 `p->Del` 在**同一锁区间**内完成，保证快照原子性。

## 验证方案

### 1. 形式化证明（修复不变量）
修复后，对 `m->Puller` 与 `m->Agents[]` 的每一处 `Select`/`Del`/`Add` 都满足：
> 访问点 A ∈ TcpM_Works 与访问点 B ∈ TcpM_Send 链，二者互斥于 `m->Lock`。

因此不可能出现「TcpM_Works 读取 puller 的同时 TcpM_Send 修改它」的交错，
数据竞争被消除。所有加锁点均为瞬时操作，不改变任何数据流向或业务逻辑
（仅是扩大既有锁的临界区以覆盖此前遗漏的 puller 访问）。

### 2. 动态验证（helgrind，Linux）
构造一个同时运行两个线程的负载：
- 线程 1：反复 `TcpM_Send(m, query, len)`（模拟前端把查询路由到 TCP 上游）；
- 线程 2：运行 `TcpM_Works(m)`（工作线程，select + 收发）。

用 helgrind 检测：

```sh
valgrind --tool=helgrind --error-exitcode=99 \
    ./dnsforwarder_test_tcpm_race 2>hg.log
grep -q "Possible data race" hg.log && echo "FAILED" || echo "0 data races"
```

修复前：`hg.log` 报告 `m->Puller` 相关 `Possible data race`。
修复后：helgrind 报告 **0 data races**，且 TCP 上游查询仍能正常收发、无崩溃。

### 3. 回归证明
本修复仅新增锁覆盖，未修改任何报文解析、连接建立、上下文匹配或数据拷贝逻辑。
既有功能（TCP 上游转发、keep-alive 复用、SOCKS 代理隧道、多上游轮询）的数据
路径保持不变；所有既有单元测试（test/tcpm_context 等）仍应通过。锁采用与现有
`TcpM_Send` / `TcpM_Works` 已有的 `m->Lock` 获取完全一致的宏，不存在新的锁顺序
反转风险（`m->Lock` 是唯一的模块级生命周期锁，所有访问点均按「获取 m->Lock →
操作共享结构 → 释放」单一顺序）。
