# SMB CHANGE_NOTIFY 协议与本项目支持情况

调研日期：2026-10-31。源码基线：`2649a0b`。本文区分协议能力、当前源码行为和需要在 AFX 上验证的行为；不把源码检查当成 AFX 实测结果。

本次 AFX 实测已完成：文件和目录创建、删除、修改及递归通知通过，详见[实测报告](validation/afx-smb-notify-2026-10-31.md)与[原始输出](validation/afx-smb-notify-2026-10-31.log)。下文协议与源码分析独立于该环境的实测范围。

## 结论

SMB2/SMB3 的 `CHANGE_NOTIFY` 可以监听共享内文件、目录的创建、删除、改名及符合过滤条件的修改。本项目已有公开的 `Directory::watch(DirectoryWatchOptions)`，返回异步 `DirectoryEvent` 流，可直接用于这项验证。前提是服务器和底层文件系统支持通知、监听账号具有目录读取权限，以及流已开始被消费。[微软 SMB2 请求规范](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/598f395a-e7a2-4cc8-afb3-ccb30dd2df7c)、[服务器处理规范](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/05869c32-39f0-4726-afc9-671b76ae5ca7)、[目录通知 API 语义](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw)。

## 监听对象、权限与过滤条件

请求携带已打开目录的 `FileId`，不能直接以普通文件句柄注册。目录句柄必须包含 `FILE_LIST_DIRECTORY`；底层不支持时返回 `STATUS_NOT_SUPPORTED`。因此监听单个文件的通常做法是监听其父目录，再按相对路径筛选事件。[服务器处理规范](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/05869c32-39f0-4726-afc9-671b76ae5ca7)。

`CompletionFilter` 可组合多位条件；`Flags=0` 仅覆盖直接子项，`SMB2_WATCH_TREE=1` 覆盖整个子树。[请求字段定义](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/598f395a-e7a2-4cc8-afb3-ccb30dd2df7c)。

| 要观察的变化 | 主要过滤位 | 含义 |
| --- | --- | --- |
| 文件创建、删除、改名 | `FILE_NAME = 0x1` | 文件名空间变化 |
| 子目录创建、删除、改名 | `DIR_NAME = 0x2` | 目录名空间变化 |
| 属性变化 | `ATTRIBUTES = 0x4` | 例如只读、隐藏属性 |
| 文件内容变化 | `SIZE = 0x8`、`LAST_WRITE = 0x10` | 大小或最后写入时间变化；同长度覆盖也应关注 `LAST_WRITE` |
| 时间戳、扩展属性、ACL | `LAST_ACCESS = 0x20`、`CREATION = 0x40`、`EA = 0x80`、`SECURITY = 0x100` | 按需启用，读取操作也可能产生时间戳事件 |
| 命名流变化 | `STREAM_NAME = 0x200`、`STREAM_SIZE = 0x400`、`STREAM_WRITE = 0x800` | 文件系统支持时可用 |

创建/删除属于名称变化；大小和写时间的通知可能受服务器缓存及刷新时机影响，不应要求每次 `write` 恰好对应一个事件。[微软目录通知说明](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw)。

监控目录 `A` 的含义是监控 `A` 内的子项。若要观察 `A` 自身的属性或时间戳修改，应监听其父目录，并筛选路径 `A`；若只监听 `A`，对子文件的写入可能直接报告子文件变化，不能把这等同于必然报告 `A` 本身的元数据变化。这一使用建议来自目录通知的子项语义。[微软目录通知说明](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw)。

## 返回数据和事件解释

响应是 `FILE_NOTIFY_INFORMATION` 链，提供 `Action` 和相对监听目录的 Unicode 路径，不能从每条事件直接得知文件内容、变化前后的属性值或操作人。通知记录没有普通文件/目录类型字段；必要时另行查询元数据，但删除后的对象可能已不可查询。[响应格式](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/14f9d050-27b2-49df-b009-54e08e8bf7b5)、[MS-FSCC 记录格式](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/634043d7-7b39-47e9-9e26-bda64685e4c9)、[Win32 记录语义](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-file_notify_information)。

| Wire action | 本项目公开事件 | 使用含义 |
| --- | --- | --- |
| `ADDED (1)` | `Added { path }` | 子项加入，包括创建或从其他目录移入 |
| `REMOVED (2)` | `Removed { path }` | 子项移除，包括删除或移到其他目录 |
| `MODIFIED (3)` | `Modified { path }` | 数据、时间或属性等变化，不能单凭该事件判断具体变化字段 |
| `RENAMED_OLD_NAME (4)` + `RENAMED_NEW_NAME (5)` | `Renamed { from, to }` | 同目录改名；项目负责配对 |
| `ADDED_STREAM (6)`、`REMOVED_STREAM (7)`、`MODIFIED_STREAM (8)` | `StreamAdded`、`StreamRemoved`、`StreamModified` | 命名流变化 |

文档差异：现行 MS-FSCC 对 `ADDED/REMOVED` 的文字重点描述跨目录改名；微软 Win32 文档仍明确解释为条目加入/移除，目录通知 API 明确包括创建/删除。不能因此把这两个 action 误解为只支持移动。具体 AFX 返回情况应由实测确认。[MS-FSCC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/634043d7-7b39-47e9-9e26-bda64685e4c9)、[Win32](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-file_notify_information)。

## 请求生命周期、取消与溢出

一次请求至多获得一次最终通知响应，服务器可以把多项变化合并为一批；持续监听需要在处理一批后继续发请求。**同一打开句柄的首个请求决定过滤器和递归范围**，规范要求后续请求沿用该配置；改变范围应重新打开目录。[服务器处理规范](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/05869c32-39f0-4726-afc9-671b76ae5ca7)、[对象存储通知算法](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1e03994f-ccce-4fc8-a370-4efa610b3e05)。

无变化时，请求可以长期挂起。服务器通常先返回带 `AsyncId` 的 `STATUS_PENDING`，之后发送最终响应；pending 只是接受请求，不能作为文件事件。取消使用同一连接上的 `SMB2 CANCEL`，根据是否收到异步标识关联目标；CANCEL 本身没有独立响应，目标操作成功取消时返回 `STATUS_CANCELLED`，取消也可能与正常完成竞态。[异步中间响应](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c1692ece-7c6d-45c8-a0e3-6b53c0483030)、[客户端取消](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/51f6a0ce-d25f-4a55-991f-98f434be4411)、[服务器取消处理](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/57bae3d3-5dd7-4a5f-92cb-fc52e2087dad)。

服务器无法把变化明细放入响应缓冲区时，可返回 `STATUS_NOTIFY_ENUM_DIR` 和空输出。这表示需要重新枚举目录以恢复状态，不能理解成“没有变化”。Windows 文档也明确指出，缓冲区溢出后原有变化记录可能全部丢弃。[SMB2 服务器规范](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/05869c32-39f0-4726-afc9-671b76ae5ca7)、[溢出与重新枚举](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw)。

据上述记录结构、合并响应和溢出行为可推断：CHANGE_NOTIFY 适合目录刷新、缓存失效和触发同步扫描，不能单独充当可靠审计日志。它不提供持久事件游标、变更内容或操作者；断线、重开句柄或溢出后应重新扫描并对账，不能声称精确恢复期间每个历史操作。

## 当前项目的公开接口与边界

以下结论来自当前源码，不代表本次 AFX 测试已经通过。

| 能力 | 当前实现位置与行为 |
| --- | --- |
| 打开监听目录 | `crates/smb/src/domain/mod.rs`：`Share::open_directory`；`DirectoryOpenOptions::open_existing()` 请求读取权限，包含监听所需权限 |
| 持续事件流 | 同文件的 `Directory::watch`，返回 `DirectoryEvents`；`DirectoryWatchOptions` 支持 `recursive(bool)` 与 `cancellation(CancelToken)` |
| 事件过滤 | `crates/smb/src/runtime/port.rs` 的 `RuntimeDirectory::watch` 固定使用 `NotifyFilter::all()`；公开 options 暂不能挑选 completion filter，调用方可按事件类型与路径过滤 |
| 实际开始时间 | runtime 使用 `stream::once(...).try_flatten()`，首次 poll 时才启动底层监听；只构造流但不调用 `next()` 不足以建立监听 |
| 单次请求和重挂起 | `crates/smb/src/resource/directory.rs` 的 `watch_stream_cancellable` 后台循环调用 `_watch_options`，每批通知后继续提交 |
| 异步与取消 | `_watch_options` 设置 `allow_async=true` 和无限等待；取消 token 与流的 Drop 触发取消，正常取消/目录清理结束流 |
| 改名 | domain 将旧名/新名记录合并为一个 `Renamed` 事件 |
| 服务器溢出 | `STATUS_NOTIFY_ENUM_DIR` 最终转换为 `Error::BufferTooSmall { data_type: "FileNotifyInformation", required: None, ... }`，该流结束；应用需要扫描和重建监听 |
| 客户端积压 | 底层事件队列容量 1024；消费落后导致 `Error::EventQueueOverflow { event: "change-notify", capacity: 1024 }` 并取消监听，不会无限积压 |
| 自动恢复 | watch 层没有自动对账扫描/断线续传，需应用处理终止与重建 |

项目已有 `crates/smb/tests/domain_api.rs` 的 `domain_spine_roundtrips_without_protocol_escape_hatches` 真实服务器测试，以及 `docs/evidence/W5-4-directory-pipe-events.md` 的历史 ONTAP 验证记录；它们是可复用入口和历史依据，不能替代本次 AFX 环境对文件/目录创建、删除、数据修改和目录元数据修改的逐项测试。

推荐实测方式：先打开共享根目录或专用测试父目录，启动并持续消费递归 watch；用另一个 SMB 连接逐项执行操作并等待相应路径事件；每步记录全部通知，允许额外元数据通知。文件写入测试应刷新/关闭写入句柄，目录修改测试应显式设置该子目录的时间戳，并在父目录监听中验证 `Modified`。验证删除时应确认删除句柄已关闭。测试开始前的订阅就绪与每步超时必须明确，避免把“流尚未 poll”误判为服务器不支持通知。
