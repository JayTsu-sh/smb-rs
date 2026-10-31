# AFX SMB CHANGE_NOTIFY 实测

日期：2026-10-31。源码基线：`2649a0b`，加本次 `notify_probe` 示例；未修改库实现。

## 结果

**可以通过本项目监听 AFX SMB 共享中的文件和目录创建、删除、修改。** 使用公开 `Directory::watch()` 接口，监听客户端和操作客户端分别创建独立 `Client`、TCP 连接和 SMB 会话；操作来自另一个客户端，事件确实由 AFX 经 SMB 返回。

| 操作 | 实际收到的公开事件 | 结果 |
| --- | --- | --- |
| 创建文件 | `Added { path: "file.txt" }` | PASS |
| 写入文件内容，flush 并关闭 | `Modified { path: "file.txt" }` | PASS |
| 修改文件最后写入时间 | `Modified { path: "file.txt" }` | PASS |
| 文件重命名 | `Renamed { from: "file.txt", to: "renamed.txt" }` | PASS |
| 删除文件并关闭句柄 | `Removed { path: "renamed.txt" }` | PASS |
| 创建子目录 | `Added { path: "child" }` | PASS |
| 修改子目录最后写入时间 | `Modified { path: "child" }` | PASS |
| 子目录重命名 | `Renamed { from: "child", to: "renamed-child" }` | PASS |
| 删除子目录并关闭句柄 | `Removed { path: "renamed-child" }` | PASS |
| 递归模式：子目录内文件创建、写入、删除 | `Added` / `Modified` / `Removed`，路径 `child\nested.txt` | PASS |
| 非递归模式：排除子目录内文件创建 | 2 秒观察窗口内未收到该文件的 `Added`；随后父目录中的重命名/删除通知仍正常 | PASS |
| 取消监听 | 5 秒内监听任务结束并关闭目录句柄 | PASS |
| 清理 | 删除本轮两个测试目录；独立新连接回查确认无本轮测试目录 | PASS |

前九项在递归和非递归两个模式分别执行。操作之间消费完待处理通知，并等待至少 300 ms 静默窗口，避免把文件创建带来的附加修改通知当成下一步写入或时间戳修改的证据。开始矩阵前先收到 `ready` 文件的创建通知，确认监听已建立。逐项断言最长等待 10 秒；不要求一次操作只产生一条通知。

原始程序输出见 [afx-smb-notify-2026-10-31.log](afx-smb-notify-2026-10-31.log)。该文件不包含密码。

## 已创建的共享与访问方式

| 配置 | 本次值 |
| --- | --- |
| 管理地址 / 系统 | `10.128.56.220`，AFX / ONTAP `9.19.1P2` |
| SVM | `svm2` |
| SMB 服务 | 新建 `AFXSMB2`，工作组 `WORKGROUP` |
| SMB 数据地址 | 本轮验证 `192.168.9.101:445` |
| UNC | `\\192.168.9.101\smb_notify_20261031` |
| 共享路径 / 卷 | `/smb_notify_20261031` / `smb_notify_20261031` |
| 卷配置 | FlexGroup，NTFS security style，100 GiB，`space-guarantee none` |
| 共享属性 | `oplocks,browsable,changenotify` |
| 共享权限 | 仅 `AFXSMB2\smbnotify`，Full Control；移除默认 Everyone ACL |
| 数据网执行机 | `10.128.56.17`，数据源地址 `192.168.9.17` |
| 管理面观察 | 两个独立会话，`SMB3_1`，`NTLMv2` / local-user |

AFX 拒绝 10 GiB FlexGroup，提示最小 100 GiB，因此按其最小值创建，不预留整个逻辑容量。原环境没有 CIFS 服务；本轮新增工作组服务、专用本地账号，并在 `svm2` 的 `default-data-files` service policy 中添加 `data-cifs`。已有 `data-nfs` 等服务保留，已有 `/pnfs_test2` 卷未改动。本轮只实测 `.101`，不把结果推广成四个 LIF 的兼容性矩阵。

共享、卷、服务及账号保留供后续使用；测试文件和临时执行程序清理。密码仅保存在当前工作机受限文件 `/root/jay/cicd/afx-smb-notify.json`（权限 `0600`），未写入本仓库。环境文档 `/root/jay/cicd/afx.md` 记录访问方式。

[ONTAP 工作组服务创建命令](https://docs.netapp.com/us-en/ontap-cli-9101/vserver-cifs-create.html)和[共享创建命令](https://docs.netapp.com/us-en/ontap-cli-9171/vserver-cifs-share-create.html)提供对应管理操作的官方说明。

## 项目用法与复现

完整可执行验证程序：[notify_probe.rs](../../crates/smb/examples/notify_probe.rs)。设置 `SMB_NOTIFY_SERVER`、`SMB_NOTIFY_SHARE`、`SMB_NOTIFY_USER`、`SMB_NOTIFY_PASSWORD` 后运行：

```bash
cargo run -p smb --example notify_probe
```

AFX 数据网不能从当前工作机直接访问。本轮在工作机构建 `x86_64-unknown-linux-musl` 静态二进制，传到 `10.128.56.17` 运行；GNU 动态程序可能不兼容跳板机的 glibc 2.34。

应用的核心用法（在已连接的 `share` 上）：

```rust
let directory = share
    .open_directory(&SharePath::new(".")?, DirectoryOpenOptions::open_existing())
    .await?;
let cancel = CancelToken::new();
let mut events = directory.watch(
    DirectoryWatchOptions::default()
        .recursive(true)
        .cancellation(cancel.clone()),
);
while let Some(event) = events.next().await {
    println!("{:?}", event?);
}
```

需要 `futures_util::StreamExt` 和上述 `smb` 类型的 import。首次消费流才启动监听；另一个任务可调用 `cancel.cancel()` 停止。监听单个文件时监控父目录并按相对路径过滤；目录本身的元数据变化也在其父目录监听中观察。

## 协议限制与本轮边界

[协议调研](../smb-notify-protocol.md)引用微软原始规范并说明 API 实现。CHANGE_NOTIFY 是可合并、可能溢出的变化提示，不是可靠审计日志；`Modified` 不携带内容差异、修改字段或操作者。服务器溢出、客户端积压或连接中断后，应用应重新枚举、对账和建立监听。

本轮没有验证断线恢复、通知溢出、高并发压力、ACL/只读属性修改、其他协议或存储内部操作引起的变化，以及主机/节点故障。目录“修改”具体验证最后写入时间，文件“修改”验证内容写入和最后写入时间，不能把它们扩展成所有修改类型均已验证。

验证命令：`cargo build -p smb --example notify_probe --target x86_64-unknown-linux-musl`、对应目标的 `cargo clippy -p smb --example notify_probe --target x86_64-unknown-linux-musl -- -D warnings`、示例 rustfmt 检查，以及 AFX 实际执行。
