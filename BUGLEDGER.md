# BUGLEDGER — dnsforwarder 缺陷清零

硬约束（事实卡）摘要：C89（`-std=c89 -pedantic-errors -Wall -Wextra`，gcc & clang，零错误）
必须为通过态；平台矩阵 Linux amd64/i386、Win x86/x64、WinXP/Vista 运行时、Android；
并发用 pthread / Win32 Thread；三条下载后端 curl/wget/禁用；spin/mutex 与 rwlock 双回退。

终止条件：连续 3 轮独立复审零新增缺陷。上限 6 轮。

---

## Round 1（2026-08-31，单会话，深度审计 + 修复）

### 覆盖清单（深度审阅的模块，每个一句话结论）

| 模块 | 结论 | 检测手段 |
|---|---|---|
| `dnsparser.c/.h` | 已知高危模式（压缩指针环、标签长度、rdata 长度、0 问题数、多问题、EDNS、CNAME 链）已全面硬化；本次未发现新缺陷 | 人工 + 4M ASan/UBSan fuzz |
| `dnsgenerator.c/.h` | 压缩/对齐/长度字段（usedlength）已硬化；`DNSCompress` memmove 边界已受控 | 人工 + fuzz |
| `iheader.c/.h` | 请求/响应头填充、多问题（QDCOUNT>1）last-wins 已硬化；未发现新缺陷 | 人工 |
| `dnsrelated.c/.h` | 纯静态类型/类查找表，低风险，未发现缺陷 | 人工 |
| `hostscontainer.c` | AAAA→A 回退与 `StringChunk_Match` 输出语义已硬化 | 人工 |
| `statichosts.c` | 文件解析/合并已硬化 | 人工 |
| `hostsutils.c` | `CombineRecursedResponse` 类型/长度校验已硬化 | 人工 |
| `linkedqueue.c` | push/fetch 与 `length` 不变式正确 | 人工 |
| `udpfrontend.c` | 接收/事件循环/关停路径已硬化 | 人工 |
| `socketpool.c` | 引用计数与 `Clear` 置 NULL 正确 | 人工 |
| `rwlock.h` | pthread_rwlock / 自旋回退双路径，单写者不变式成立 | 人工 |
| `readline.c` | `ClearAnnotation` 指针 UB、`EliminateFootSpace` 索引已硬化 | 人工 |
| `readconfig.c` | 别名环检测、续行修复、空值处理已硬化 | 人工 |
| `mcontext.c` | sweep 释放、reset-before-delete、比较器已硬化 | 人工 |
| `common.h` | **修复点**：缺 C99 标识符 shim（见下） | 严格编译 |
| `utils.c` | **修复点**：`SetSocketTimeout` 非常量聚合初始化（见下） | 严格编译 |

### 未覆盖模块（本轮未深度审阅，理由：单会话预算，按风险优先级 deferred 至 R2/R3）

`array.c`(已有 array_overflow 测试) `bst.c` `cacheht.c` `cachettlcrtl.c` `simpleht.c` `stringchunk.c`
(上述均有测试，相对已覆盖)；`pipes.c` `winmsgque.c`(Windows) `tcpm.c` `tcpfrontend.c` `udpm.c`
`socketpuller.c` `timedtask.c` `ptimer.c` `ipchunk.c` `stablebuffer.c` `stringlist.c` `addresslist.c`
`goodiplist.c` `ipmisc.c` `filter.c` `domainstatistic.c` `downloader.c` `hosts.c` `dynamichosts.c`
`logs.c` `mmgr.c` `main.c`。这些多数已带专项修复测试，但本轮未逐行复核，列为待覆盖。

### 发现与修复

| 编号 | 指纹 | 级别 | 状态 | 证据 |
|---|---|---|---|---|
| 1 | `common.h:__STRICT_ANSI__:snprintf|vsnprintf|va_copy` | S3 | fixed | 严格编译前后对比 + test/c89_shim |
| 2 | `utils.c:SetSocketTimeout:1440:nonconst-aggregate-init` | S3 | fixed | 严格编译前后对比 + test/c89_shim |

说明：全树在 `make`(gnu) 构建下零错误零崩溃；全部 69 个既有回归测试 + 新增 1 个 = 70/70 通过；
4M 次 ASan/UBSan DNS 往返 fuzz 零错误。本轮在已审阅的 14 个模块中未发现新的 S1/S2 缺陷
（代码已处于多轮硬化状态）。唯一可落实的新缺陷是 C89 严格构建不通过（违反事实卡硬约束 #1），已修复。

注：`-Wunused-parameter` 警告在 dnsparser.c / utils.c 等既有代码中大量存在，属预置现象、
非本轮引入、非严格构建的“错误”，不在本轮修复范围内（属 S4/既有，留待专项清理）。

### 验证手段与结果摘要
- 严格编译：gcc `-std=c89 -pedantic-errors -Wall -Wextra -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -I.`
  编译全部非 Windows 源文件：**零错误**（修复前 `snprintf`/`va_copy` 隐式声明错误 + utils.c:1440 错误）。
- 全回归：`test/*/run.sh` 70/70 通过。
- fuzz：`dnsparser`+`dnsgenerator`+`iheader` 往返 4M 次，ASan+UBSan 零错误。
- Windows/MinGW：未验证（本环境无 MSVC/MinGW 工具链；改动经 `__STRICT_ANSI__` 守卫，MSVC 不受影响）。

---

## Round 2（继续会话，深度审计 + 实证验证）

### 覆盖清单（深度审阅 + 实证）

| 模块 | 结论 | 检测手段 |
|---|---|---|
| `downloader.c` | 三后端（libcurl/wget/禁用）空 URL 短链、写回调短写、merge 的 fputc/fclose/截断、shell 引号拒绝、snprintf 边界、HTTP 4xx/5xx 拒绝、abort 中断重试环，均已硬化 | 人工 |
| `cacheht.c` | rehash/删除/关停遍历、2D 空闲表 KeyNext/ValNext 截断回退、对齐、IsStructureSane 全字段校验（含环检测）已硬化 | 人工 + 压力 |
| `simpleht.c` | Expand 回滚、size_t 乘法溢出校验、memcpy 长度、Enum/Find Next 链已硬化 | 人工 + 压力 |
| `CacheHT_IsStructureSane` 调用点 | 已确认 `dnscache.c:163` 在加载路径调用，OOB-write-from-corrupted-cache 担忧已闭合 | 代码指纹核查 |

### 实证压力测试（Round 2 新增，非提交，仅取证）
- SimpleHT：随机 key/length/重复 key，insert+find+enum+free 共 **300k** 次（覆盖 Expand 全路径），ASan+UBSan 零错误。
- CacheHT：在 1MB 映射上随机 chunk size insert/get/remove 共 **20k** 节点（覆盖 2D 空闲表复用、NodeChunk 增长、删除回链），ASan+UBSan 零错误。

### Round 2 发现
- 未发现新的 S1/S2 缺陷。已审阅模块均处于多轮硬化状态。
- 唯一已落实修复仍是 R1 的 C89 严格构建缺陷（已提交 `ac199d3`）。

### 未覆盖模块（继续 deferred）
剩余约 40 模块：`array` `bst` `cachettlcrtl` `stringchunk` `ipchunk` `stablebuffer`
`stringlist` `addresslist` `goodiplist` `ipmisc` `filter` `domainstatistic`
`hosts` `dynamichosts` `logs` `mmgr` `main` `pipes`(Win) `winmsgque`(Win)
`tcpm` `tcpfrontend` `udpm` `socketpuller` `timedtask` `ptimer`。多数已有专项修复测试，
但本轮未逐行复核，列为待覆盖。

### 验证手段与结果摘要（累计）
- 严格编译（R1 修复后）：全部非 Windows 源文件零错误。
- 全回归：70/70 通过。
- 实证 fuzz/压力：DNS 往返 4M + SimpleHT 300k + CacheHT 20k，ASan+UBSan 全部零错误。
- 终止计数：R1 有缺陷（已修），计数清零；R2 在已审阅子集内零新增，但覆盖未全覆盖 60 模块，
  尚不计为“干净轮次”。需继续 R3 直至连续 3 轮独立复审零新增且覆盖充分。

注：R2 未改动任何源文件，工作树与 R1 提交 `ac199d3` 一致。
