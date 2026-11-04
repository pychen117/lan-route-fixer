# Windows 工具

这个目录放两类东西：

| 文件 | 用途 |
| --- | --- |
| `fix-lan.cmd` | **一键入口**：双击即可（自动请求管理员权限），跑完自动显示状态。也接受 `status` / `apply` / `remove` / `watch` / `install` / `uninstall` 参数 |
| `pin-lan.ps1` | 独立可用的 PowerShell 工具：读 `~/.ssh/config`，给局域网主机加 `/32` 主机路由，让它们不再被 aTrust / EasyConnect 的隧道抢走 |
| `probe_winapi.py` | 只读探针：用 ctypes 调 IP Helper API，打印路由表、地址表、网卡表，用来核对结构体布局与真实行为 |

## 为什么会丢流量

Sangfor aTrust 连上后，会把 `10/8`、`172.16/12`、`192.168/16` 拆成几十条
长前缀路由塞进它的隧道网卡，metric 全是 0。Windows 选路先比前缀长度，再比
metric，于是：

```
192.168.4.0/24   -> WLAN（物理网卡，Local，metric 256）   ← 本来应该走这里
192.168.4.64/26  -> aTrustVNIC（隧道，metric 0）          ← aTrust 加的，赢了
```

`192.168.4.94` 落在 `/26` 里，SSH 就断在隧道那头。Linux 上可以用
`ip rule` 把目标钉到独立路由表；**Windows 只有一张路由表**，没有对应物，
所以这里用另一条更简单也更硬的办法：给每台主机加一条 `/32` 主机路由。

`/32` 比 aTrust 的任何 `/25`、`/26` 都长，最长前缀优先，所以它永远赢，
而且 aTrust 不会去删一条不是它自己的主机路由（删了 watch 也会补回来）。

## 快速开始

**最简单：双击 `tools\windows\fix-lan.cmd`。** 它会自己弹 UAC 提权、写入三条
`/32` 路由、再打印一遍状态，最后停住等你按键。日常只需要这一个文件。

也可以在命令行里调用（Windows 自带的 PowerShell 5.1 用 `powershell`，
装了 PowerShell 7 才有 `pwsh`）：

```powershell
# 一条命令完成修复 + 验证
.\tools\windows\fix-lan.cmd

# 只看现状（不需要管理员）
.\tools\windows\fix-lan.cmd status
```

等价于直接调用 `pin-lan.ps1`：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\windows\pin-lan.ps1 -Action status
```

`status` 输出会把 6 台 SSH 主机列出来：落在物理网段里的标 `pin`（还差一条主机路由），
已经钉好的标 `pinned`，落在隧道网段里的标 `skip` 并说明现在走的是哪条路由、
哪个网卡、网关是谁。

真正写入需要**管理员**（`fix-lan.cmd` 会自动提权；直接调脚本则要自己开管理员窗口）：

```powershell
# 以管理员身份打开 PowerShell，然后：
Set-ExecutionPolicy -Scope Process Bypass -Force
.\tools\windows\pin-lan.ps1 -Action apply
```

取消：

```powershell
.\tools\windows\pin-lan.ps1 -Action remove
# 或者一键入口：
.\tools\windows\fix-lan.cmd remove
```

### 掉线后自动补回来

aTrust 重连、DHCP 续租、Wi-Fi 切换都可能清掉主机路由。两种常驻方式：

```powershell
# 方式一：前台守护（关掉窗口就停）
.\tools\windows\pin-lan.ps1 -Action watch -WatchInterval 10

# 方式二：注册登录计划任务（管理员，开机登录后自动以最高权限常驻）
.\tools\windows\pin-lan.ps1 -Action install
Get-ScheduledTask -TaskName LanRouteFixer | Format-List
.\tools\windows\pin-lan.ps1 -Action uninstall   # 取消
```

`watch` 每 `-WatchInterval` 秒重新规划一次，只在状态变化时打印一行，平时安静。

### 其他参数

| 参数 | 说明 |
| --- | --- |
| `-SshConfig PATH` | 换一个 SSH 配置（默认 `%USERPROFILE%\.ssh\config`） |
| `-Adapter NAME` | 强制指定物理网卡（网卡名或 ifIndex），默认自动选 |
| `-WatchInterval 10` | `watch` 的轮询秒数 |
| `-AsJson` | `status` 输出 JSON，便于脚本消费 |

退出码：`0` 正常，`1` 出错（含未提权时执行 `apply` / `watch` / `install`）。

## 它怎么判断“物理网卡”

跳过隧道与虚拟网卡（名字或描述里带 tunnel / aTrust / Sangfor / Tailscale /
Wintun / WireGuard / VPN / Loopback / Hyper-V / vEthernet 等），
只保留 `Status=Up`、`MediaType` 是 `Native 802.11`（Wi-Fi）或 `802.3`（以太网）、
并且有非 `169.254.*` IPv4 地址的网卡。主机地址必须落在某块物理网卡的
子网里才会被钉；否则只报告它现在走的是哪条隧道。

> 注意：`Get-NetAdapter` 的 `ifType` 在这些系统上是空的，`MediaType` 才是可靠
> 判据；`Win32_NetworkAdapter.PhysicalAdapter` 对隧道网卡也返回 True，不能信。

## 与 lan-route-fixer 的关系

`pin-lan.ps1` 是给“只想马上把 SSH 修好”的场景准备的，零依赖、单文件、不读
本项目的配置。

项目本身也已经支持 Windows（同一个 `NetworkBackend` 协议 + `reconcile` 决策层）：

```powershell
# 从 SSH 配置导入局域网主机（只读预演）
python -B src\usr\bin\lan-route-fixer import-ssh --dry-run

# 查看每台主机的路由状态（不需要管理员）
python -B src\usr\bin\lan-route-fixer status

# 管理员 PowerShell 里执行真正的修复
python -B src\usr\bin\lan-route-fixer fix
```

两者写的是同一类东西（`/32`、下一跳 `0.0.0.0`、metric 0），但互相独立：
用 `pin-lan.ps1` 不需要装 Python，用 `lan-route-fixer` 则能复用配置、诊断和
守护逻辑。不要同时让两边各跑一个 watch，重复无所谓，只是多一份轮询。

## 限制

- 只处理 IPv4（aTrust 的 IPv6 场景没有验证过）。
- 不改网卡 metric，不改 aTrust 自己的路由，只加最长前缀主机路由。
- 需要管理员：Windows 不允许普通用户写路由表，也没有 `sudo` 那样的“单次提权”。
- `watch` 依赖进程活着；要长期生效请用 `install` 注册计划任务。
- 判断“物理网卡”靠名字/描述启发式，遇到奇怪的网卡名可以用 `-Adapter` 指定。

## probe_winapi.py

只读探针，不写任何东西：

```powershell
python -B tools\windows\probe_winapi.py
```

会打印结构体尺寸、前向表行数、每块网卡的 ifIndex/名称/描述/IfType/状态/地址，
以及 `GetBestRoute2` 对几个目标地址的选路结果。移植 ctypes 结构体时用它核对
`IpAddressPrefix` 必须是 32 字节（`SOCKADDR_INET` 的联合体里有 `ULONG`，
对齐是 4，不是 2）、`IpForwardRow2` 必须是 104 字节。