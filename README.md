# lan-route-fixer

把选中的局域网设备「钉」在物理网卡上，避免 VPN 全隧道抢走私网路由后设备失联。

典型场景：

- aTrust / EasyConnect / 深信服等企业零信任客户端
- Deskflow / Synergy / Barrier / Input Leap 键鼠共享
- RDP / VNC / SSH / Sunshine 等远程桌面
- NAS / SMB / NFS 文件共享
- 打印机、IP 摄像头、IPMI/BMC、智能家居设备
- 内网 GitLab、数据库、开发服务器、树莓派

## 你是否遇到了这个问题？

```
先打开 aTrust，再连 SSH      -> 连不上（超时 / 无法路由到主机）
先连 SSH，再打开 aTrust      -> 可以，但新开的连接还是可能失败
```

这是 aTrust 这类客户端的典型行为：连接时它会枚举整个私网空间
（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`），把每一个网段
**拆成 `/25`…`/32` 的碎片**，逐条塞进路由表指向它的 `utun7` 隧道设备。
在本机实测（aTrust 2.5.16）里，`192.168.4.0/24` 被拆成这样：

```
192.168.4.0/25     dev wlp0s20f3   # 恰好让给物理网卡
192.168.4.128/26   dev utun7       # 抢走
192.168.4.192/27   dev utun7       # 抢走
192.168.4.224/29   dev utun7       # 抢走
192.168.4.232/30   dev utun7       # 抢走
192.168.4.236/31   dev utun7       # 抢走
192.168.4.239/32   dev utun7       # 抢走
192.168.4.240/28   dev utun7       # 抢走
```

注意 `192.168.4.19`（`u55c`）恰好落在被让出的 `/25` 里，所以它「运气好」能用；
而 `192.168.4.94`、`192.168.4.234` 一旦被划进 `utun7` 的碎片，就会直接失联。
**更麻烦的是这套碎片划分不是固定的**：它会随 aTrust 的连接过程变化，
所以「昨天能用、今天不能用」是常态，而不是玄学。

2.0.x 版本的做法是「加一条更长前缀的路由」：

```sh
ip route replace 192.168.4.169/32 dev wlp0s20f3
```

方向是对的，但有两个致命弱点，也正是 2.1.0 要解决的问题。

### 弱点一：修得太慢（最长 30 秒空窗）

aTrust 在**连接瞬间**重写路由表。如果它把我们的 `/32` 删掉或覆盖，
2.0.x 只能等下一次 systemd timer 触发（默认 30 秒）才修好。
而 TCP 在几秒内就会重传失败，于是你看到的就是「SSH 断了 / 连不上」。

2.1.0 增加了 **rtnetlink 事件驱动守护进程**：直接订阅内核的
`RTM_NEWROUTE` / `RTM_DELROUTE` / `RTM_NEWLINK` 通知，路由一变就立刻重新对齐，
而不是等下一次轮询。

实测延迟（`tools/verify-namespace` 在真实内核上循环抢走路由并计时）：

| | 修复延迟 |
| --- | --- |
| 2.0.x（30 秒 timer） | 最长 **30 秒** |
| 2.1.0（事件驱动） | **约 0.33 秒**（3 次测量 0.33 / 0.34 / 0.34） |

这 0.33 秒不是内核通知的开销，而是刻意加的 **250ms 去抖**：aTrust 连接时会
一次灌进几百条路由，等这一批结束再统一处理，比处理 300 次更快也更安全。

### 弱点二：主表里的路由随时会被再抢一次

只在 `main` 表里放一条恰好正确的路由，是「碰巧对」，不是「锁定对」。
任何一次表重写都可能把它拿走。

2.1.0 默认启用**策略路由**：

```sh
ip rule add pref 1200 to 192.168.4.19/32 lookup 168   # 先看我们的表
ip route replace 192.168.4.19/32 dev wlp0s20f3 table 168 proto 66
```

`ip rule` 的优先级（1200）远高于内核查 `main` 表的默认规则（32766），
所以**只要规则在，aTrust 怎么改主表都影响不到这些目标**；
而 aTrust 不会去动别人加的 `ip rule`。

### 弱点三：反复弹授权框

2.0.x 的 GUI 是**自己**用 `pkexec` 改路由的。PolicyKit 的 `auth_admin_keep`
只缓存几分钟，所以只要 aTrust 反复把路由抢回去，你就会**无限次**被要求输密码。
更糟的是这会养成"看到密码框就输"的坏习惯。

2.1.0 把修复交给已经在 root 下运行的守护进程（D-Bus）：

```sh
# GUI 点"立即修复"时走的是这条：守护进程收到请求 → 重读配置 → 修复
# 全程没有密码框，因为没有任何权限被下放给调用方
busctl call io.github.pychen117.LanRouteFixer /Daemon \
    io.github.pychen117.LanRouteFixer.Control Repair
```

安全性并没有因此变松：**目标永远来自配置文件，不来自调用方**。
用户能通过 D-Bus 做的唯一一件事，就是让守护进程"现在再检查一遍"——
而他本来只要等下一个内核路由事件就能得到同样结果。
`pkexec` 仍然保留，用于"目标不在任何配置文件里"这种守护进程无法覆盖的情况。

## 2.2.0：一个窗口的界面 + 清理机制

2.1.0 解决的是"修得快不快"，2.2.0 解决的是"用久了界面越点越乱、残留越堆越多"。

### 侧栏单窗口，不再叠三层

之前的界面打开设置是**第二个窗口**，点编辑目标又是**第三个窗口**，
关的时候要一层层关回去，很容易迷路。2.2.0 改成
`Adw.NavigationSplitView`：左侧栏（概览 / 修复目标 / 路由与后台 / 配置文件 /
清理 / 运行记录），所有内容都在右半边，编辑目标作为 navigation page 滑入，
左上角返回。侧栏带徽标（几个目标异常、几项可清理），不用点进去就知道状态。

![界面总览](docs/screenshots/overview.png)

![修复目标](docs/screenshots/targets.png)

### 配置文件页：文件是你的

「配置文件」页显示配置文件的真实路径和**原始 JSON**，可以直接改、可以校验、
可以保存，也可以删除整个文件重新开始。保存前会先解析一遍 JSON，
语法错误会被拒绝而不是写坏文件；无法识别的键会原样保留（和 CLI 行为一致）。

![配置文件](docs/screenshots/config.png)

### 清理页：别让残留的 IP 堆成屎山

两类垃圾会慢慢堆积：

1. **路由与规则残留**：目标删掉或停用后，之前装的 `proto 66` 路由和
   `ip rule` 不一定有人回收（守护进程运行时才会顺带回收；没开守护进程、
   配置被手工删掉、或换机器时就会留下）。
2. **配置里的僵尸条目**：`scan` 会把整个局域网的手机、打印机都扫出来，
   真正启用的往往只有两台，其余的作为「已停用」条目永远躺在配置里。

清理页把两者列出来，勾选后删除；命令行是同一套实现：

```sh
lan-route-fixer prune                     # 预演，只列不改
lan-route-fixer prune --yes               # 真正清理配置条目（不需要 root）
sudo lan-route-fixer prune --yes          # 连路由和规则一起删（需要 root）
lan-route-fixer prune --routes --days 7   # 只看路由残留，保留窗口临时改成 7 天
```

![清理](docs/screenshots/cleanup.png)

判定规则刻意保守：

- **只碰自己装的东西**：路由必须带 `proto 66`，规则必须指向本工具的表；
  Tailscale 的规则、VPN 的路由、DHCP 默认路由一律不动。
- **只清理已停用的目标**：开启中的目标无论离线多久都不会被建议删除——
  那是用户的决定，不是垃圾。
- **不碰别人的配置文件**：非 root 运行时只会读「系统配置 + 自己的配置」，
  也只改自己的（只有 root 能看到所有用户的配置，因为守护进程必须覆盖它们）；
  而路由归属始终按「所有已发现配置 + 显式 `--config`」计算，所以即使
  `--config` 指向一个很窄的文件，也不会把别的配置正在用的路由当成垃圾。
- **保留窗口可配**：`prune_after_days`（默认 30 天）。`scan` 会把每次看到的
  邻居写进 `~/.config/lan-route-fixer/discovered.json`，
  这样「上周刚停用」和「三月就消失的设备」可以区分开。
- **失败就说失败**：删不掉的条目会明确报错并让命令返回非 0，
  而不是假装清理成功。

## 安装

从源码构建 `.deb`：

```sh
cd lan-route-fixer
dpkg-buildpackage -us -uc -b
sudo apt install ../lan-route-fixer_2.5.0-1_all.deb
```

安装后：

- CLI：`lan-route-fixer scan|check|fix|list|status|doctor|prune|daemon|config ...`
- TUI：在终端里直接输入 `lan-route-fixer`（不带参数）就打开全屏控制台
- GUI：应用菜单打开「局域网路由修复」
- 后台：`lan-route-fixer-daemon.service`（事件驱动，实测约 0.33 秒修复）
  + `lan-route-fixer.timer`（60 秒兜底）+ NetworkManager dispatcher

## 快速开始（aTrust 场景）

```sh
# 0. 先看全貌：在终端里直接输入（不带参数）就打开全屏控制台
lan-route-fixer

# 1. 看看现在到底哪条路在抢流量
lan-route-fixer doctor

# 2. 把常用设备加进来（SSH 别名里的 IP 一定要加全）
lan-route-fixer add 192.168.4.19  --name u55c
lan-route-fixer add 192.168.4.234 --name eda_T2
lan-route-fixer add 192.168.4.94  --name 4090-1

# 3. 立刻修复（会弹一次授权）
lan-route-fixer fix

# 4. 确认后台守护进程在跑（这才是 0.33 秒级修复的关键）
systemctl status lan-route-fixer-daemon.service
lan-route-fixer status --daemon

# 5. 用久了想清理残留（先预演，确认后再加 --yes）
lan-route-fixer prune
```

> **易踩的坑**：本工具只保护**你配置过**的目标。
> 如果 `192.168.4.94` 没加进来，它现在可能「运气好」落在 aTrust 让出的
> `/25` 里，等 aTrust 换个碎片划分就会失联。
> 用 `lan-route-fixer check` 看一遍，或者直接把 SSH 配置里的局域网 IP 全加进来。
> 同时注意：**公司内网地址（例如 `10.10.60.101`）不要加**，
> 那些本来就应该走 VPN。

如果设备会频繁变动、或者懒得逐个维护，可以让某台设备连带保护整个子网
（只影响该网段，不会波及公司内网）：

```sh
lan-route-fixer add 192.168.4.19 --name "家里局域网" --expand
# 等价于给 192.168.4.0/24 装一条走物理网卡的路由，192.168.4.x 全部受保护
```

`--expand` 是**按目标**生效的，所以可以只对家庭网段开启、对其它目标保持单机保护。
全局开关是 `expand_host_targets`，默认关闭。

`doctor` 会直接点名「哪条更宽的路由把流量送去了 `utun7`」：

```
✗ u55c 状态异常：wrong-interface
    流量经由 utun7 而不是 wlp0s20f3
    → 更宽的路由 192.168.4.128/26 正在把流量送去 utun7；
      启用 routing_mode=rule 或保持守护进程运行可避免
```

## TUI 控制台

在终端里直接输入 `lan-route-fixer`（带参数则按子命令执行，`lan-route-fixer tui`
也可以显式打开）就会进入全屏控制台：左边是每台目标的卡片
（`SECURED` / `CAPTURED` / `NO ROUTE` / `OFF`），右边是路由完整性雷达和
`TARGETS / SECURED / CAPTURED` 计数、网卡/隧道/aTrust/权限/看门狗/路由数，
底部是事件流和快捷键。日常操作不用记子命令。

```
┌──────────────────────────────────────────────────────────────┐
│   LAN ROUTE FIXER    //  A T R U S T   D E F E N S E   G R I D │
├────────────────────────────────┬─────────────────────────────┤
│ ▌ 4090-1              SECURED  │       ROUTE INTEGRITY       │
│   192.168.4.94/32              │             TARGETS 03      │
│   WLAN  ──▸ WLAN               │             SECURED 03      │
│   challenge_4090     CAPTURED  │             CAPTURED 00     │
│   192.168.4.234/32             │      ·····▸·····            │
│   WLAN  ──▸ aTrustVNIC         │                             │
└────────────────────────────────┴─────────────────────────────┘
```

| 键 | 动作 |
| --- | --- |
| `↑` `↓` | 选择目标；`↵` 打开详情（期望网卡、当前网卡、覆盖它的更宽前缀、路由/规则状态） |
| `s` | 重新扫描（目标、网卡、看门狗状态一起刷新） |
| `f` | 修复选中目标（未选中则修全部）；需要提权时自动走 `pkexec` |
| `i` | 从 `~/.ssh/config` 导入局域网主机：先预演，按 `y` 才写入 |
| `d` | 诊断（等价于 `doctor`，结果显示在浮层里） |
| `w` | 看门狗：安装/卸载后台自动修复，状态显示在 `WATCHDOG` 行 |
| `?` | 帮助浮层；`Esc` 关闭浮层；`q` 或 `Ctrl-C` 退出 |

几点说明：

- 只依赖标准库（不用 `curses`），所以 Windows 终端里也能跑；宽度小于 92 列
  自动切紧凑布局，小于 60×12 直接提示「窗口太小」。
- **只读优先**：只有 `f`（修复）、`i` 里按 `y` 的写入、`w` 的安装会改系统，
  其余动作都只是看。
- 有参数时仍然是普通 CLI（`lan-route-fixer status` 等）；桌面启动器没有 tty，
  仍然打开 GTK 界面。想强制其中一个：`LAN_ROUTE_FIXER_GUI=1 lan-route-fixer`
  强制 GTK，`lan-route-fixer tui` 强制终端界面。

## 命令参考

| 命令 | 说明 |
| --- | --- |
| `scan` | 扫描局域网邻居（ARP 邻居表 + mDNS 反解），输出 JSON，并记录"最后一次见到"的时间 |
| `check [--json]` | 检查所有已启用目标，退出码 0/1 便于脚本使用 |
| `fix [--quiet] [--direct]` | 修复；默认先请守护进程代劳（无授权），`--direct` 强制走 pkexec |
| `status [--json] [--daemon]` | 目标当前路由状态；`--daemon` 读守护进程状态文件 |
| `doctor [--json] [--no-probe] [--port N]` | 诊断：环境 / 路由 / 后台 / 连通性，并给出可执行建议 |
| `prune [--yes] [--routes] [--targets] [--days N] [--json]` | 清理残留路由/规则与早已不用的目标；默认只预演 |
| `daemon [--once] [--dry-run] [--interval N] [--dbus]` | 事件驱动修复循环；`--dbus` 额外提供控制接口 |
| `list / add / remove / enable / disable / set-interface` | 目标管理 |
| `config show\|get\|set\|paths` | 读写配置项 |
| `run [--once]` | 2.0.x 的前台循环（保留，等价于 `daemon`） |
| `tui [--interval N]` | 全屏终端控制台；终端里不带参数的 `lan-route-fixer` 默认打开它 |

常用配置项：

```sh
lan-route-fixer config set routing_mode rule        # rule（默认）| main
lan-route-fixer config set rule_table 168           # 1..252
lan-route-fixer config set rule_preference 1200
lan-route-fixer config set interval_seconds 10      # 守护进程的兜底轮询周期
lan-route-fixer config set expand_host_targets true # 把 /32 扩成所在子网
lan-route-fixer config set prune_after_days 30      # 停用多久没出现才建议清理
```

## 路由模型

```
                    ┌────────────────────────────────┐
 192.168.4.19 ────▶ │ ip rule pref 1200              │ 命中：查表 168
                    │   to 192.168.4.19/32 lookup 168│
                    └───────────────┬────────────────┘
                                    │
                    ┌───────────────▼────────────────┐
                    │ table 168                      │
                    │  192.168.4.19/32 dev wlp0s20f3 │ ← 我们装的，proto 66
                    └───────────────┬────────────────┘
                                    │ 未命中时继续
                    ┌───────────────▼────────────────┐
                    │ table main（aTrust 在这里刷表）│
                    └────────────────────────────────┘
```

- **策略路由**（`routing_mode=rule`，默认）：路由装在独立表 `168`，
  由一条 `ip rule` 引导；aTrust 重写 `main` 表无效。
- **主表兼容模式**（`routing_mode=main`）：只装 `ip route replace`，
  行为与 2.0.x 一致，适合极少数不兼容策略路由的环境。
- **proto 66 标记**：我们装的每条路由都带 `proto 66`，
  因此可以被准确识别、统计和回收，也不会误删别人的路由。
- **源地址固定**：路由带上 `src`，避免 VPN 存在时内核选错源地址。
- **规则垃圾回收**：目标被删除或停用后，对应的 `ip rule` 会自动清理
  （只清理指向我们自己表的规则，绝不动 Tailscale / 其他工具的规则）。

![路由与后台](docs/screenshots/routing.png)

## 后台服务

| 单元 | 作用 | 延迟 |
| --- | --- | --- |
| `lan-route-fixer-daemon.service` | 订阅 rtnetlink，路由一变就修；同时提供 D-Bus 控制接口 | 实测 ~0.33s |
| `lan-route-fixer.timer` | 60 秒兜底轮询（守护进程没跑时的最低保障） | ≤60s |
| NetworkManager dispatcher | 网卡/VPN 状态变化时触发一次修复 | 秒级 |

三者可同时存在（修复是幂等的）。只想用其中一个：

```sh
sudo systemctl disable --now lan-route-fixer.timer
sudo systemctl enable  --now lan-route-fixer-daemon.service
```

守护进程会尊重每个配置文件的 `auto_fix`：为 `false` 时只检查、不修改。

### D-Bus 控制接口

通过 `lan-route-fixer-daemon.service`（`--dbus`）暴露在系统总线上：

| 成员 | 作用 |
| --- | --- |
| `Repair() -> s` | 立即重读配置并修复，返回 JSON 报告 |
| `GetStatus() -> s` | 返回守护进程最近一次状态（JSON） |
| `Reload()` | 触发一次重读（守护进程本来每次都会重读配置） |
| `StateChanged(s)` | 每次修复后广播状态 |
| `Version`（属性） | 接口版本，只读 |

服务名 `io.github.pychen117.LanRouteFixer`，对象路径 `/Daemon`，
接口 `io.github.pychen117.LanRouteFixer.Control`。
访问控制在 `/usr/share/dbus-1/system.d/`（只有 root 能注册名字），
方法调用另外还会校验调用方 UID 与守护进程一致。

```sh
busctl introspect io.github.pychen117.LanRouteFixer /Daemon
busctl call io.github.pychen117.LanRouteFixer /Daemon \
    io.github.pychen117.LanRouteFixer.Control GetStatus
```

## CLI 用法（更多示例）

```sh
# 扫描
lan-route-fixer scan --pretty

# 添加网段（网卡留空则自动按同网段匹配）
lan-route-fixer add 192.168.8.0/24 --name "NAS 网段" --interface eth0

# 修改 / 停用 / 删除
lan-route-fixer set-interface 192.168.4.19 auto
lan-route-fixer disable 192.168.4.19
lan-route-fixer enable  192.168.4.19
lan-route-fixer remove  u55c

# 系统级 / 无头配置
sudo mkdir -p /etc/lan-route-fixer
sudo lan-route-fixer --config /etc/lan-route-fixer/config.json add 192.168.4.19

# 前台调试（看它到底在做什么）
sudo lan-route-fixer daemon --interval 5
```

## 配置

- 用户配置：`~/.config/lan-route-fixer/config.json`
- 系统级配置：`/etc/lan-route-fixer/config.json`
- 守护进程状态：`/run/lan-route-fixer/state.json`（无权限时回退到用户配置目录）
- 邻居发现缓存：`~/.config/lan-route-fixer/discovered.json`（`scan` 写入，
  `prune` 读取；删掉它只会让"多久没出现"重新开始计时）

```json
{
  "targets": [
    { "name": "u55c", "address": "192.168.4.19", "interface": "", "enabled": true },
    { "name": "家里局域网", "address": "192.168.4.234", "interface": "", "enabled": true, "expand": true },
    { "name": "NAS 网段", "address": "192.168.8.0/24", "interface": "eth0", "enabled": true }
  ],
  "interval_seconds": 10,
  "auto_fix": true,
  "autostart": false,
  "routing_mode": "rule",
  "rule_table": 168,
  "rule_preference": 1200,
  "expand_host_targets": false,
  "prune_after_days": 30
}
```

2.0.x 的配置可以直接沿用：`ip` 作为 `address` 的别名仍然有效，
无法识别的键在保存时原样保留，新增键会自动补默认值。

`interface` 留空表示自动选择：先选与目标同网段的网卡，再选默认出口网卡。
`prune_after_days` 只影响 `prune` / 清理页的**建议**，不会自动删除任何东西。

## 安全边界

提权只发生在 `/usr/libexec/lan-route-fixer/lan-route-helper`（pkexec + polkit），
它只接受：

- 私有 IPv4（`10/8`、`172.16/12`、`192.168/16`、`169.254/16`）
  或 ULA / 链路本地 IPv6 目标；
- 已存在、非隧道、非回环的网卡（物理网卡，或 bridge/bond/vlan）；
- 路由表限定为 `1..252` 或 `main`；`local`/`default`/`253`/`254`/`255` 会被拒绝；
- 只会执行 `ip route replace` 和 `ip rule add/del`，没有 flush、没有 shell。

清理路由残留（`sudo lan-route-fixer prune --yes`）直接用 `ip route del` /
`ip rule del`，因此要 root；它只会删除"扫描时确认带 `proto 66`、
或指向本工具表"的条目，绝不会去动别人的路由。

守护进程可以额外用 systemd 沙箱限制（见单元文件里的
`CapabilityBoundingSet` / `ProtectSystem`）。

## 验证

```sh
# 单元测试（不需要 root，189 项）
python3 -m unittest discover -s tests -t .

# 真实内核端到端验证（不需要 root，在私有网络命名空间里跑，26 项检查）
bash tools/verify-namespace

# GTK 界面冒烟测试（不需要人点：建好每一页、切页、打开编辑器、渲染清理结果）
python3 tools/gui-smoke

# 把每一页渲染成 PNG（默认写进 docs/screenshots/）
python3 tools/gui-screenshot

# 在你自己的机器上验证（需要 root，会临时改路由，默认用空闲表 193 并自动还原）
sudo bash tools/verify-install
```

`tools/verify-namespace` 用 `unshare -Urn` 拿到一个私有网络命名空间，
在里面用**真实的 `ip` 和真实的内核路由代码**验证全部核心论断：

- `ip rule add` / `ip route replace ... table N proto 66` 的真实行为；
- 策略路由确实**抢在 main 表之前**（VPN 把整个 `/24` 抢走，目标仍走物理网卡）；
- VPN 再次重写 main 表后规则依然生效；
- daemon 修复被劫持的路由，并保留 `proto 66` 和固定源地址；
- **修复延迟实测**（3 次抢路由并计时，约 0.33 秒）；
- 停掉守护进程后没人再修复（证明延迟来自事件而不是轮询）；
- 删除目标后 `ip rule` 与路由被回收；
- `routing_mode=main` 兼容模式的行为；
- `prune` 在真实路由表里只回收带 `proto 66` 的孤儿路由/规则，
  同表里别人 `proto boot` 的路由和已配置目标的路由都不会被动。

`tools/gui-smoke` 在没有人类点击的情况下走完整棵控件树（40+ 项断言），
`tools/gui-screenshot` 顺手生成下面这些截图。

`--config` 选项、`fix --direct`、D-Bus 接口、`prune` 的预演/执行/失败路径
等则分别有单元测试覆盖。

## 项目结构

Linux 和 Windows 是**平行的两个平台目录**：`debian/` 管 Debian 打包，
`windows/` 管 Windows 构建、exe 与独立工具；Python 实现只有一份，在 `src/`。

```
debian/                                        Debian 打包
windows/                                       Windows 构建与独立工具
    fix-lan.cmd        一键入口（自动请求管理员权限）
    pin-lan.ps1        独立 PowerShell 工具（status/apply/remove/watch/install）
    entry.py           PyInstaller 入口（命令行 exe）
    gui_entry.py       PyInstaller 入口（GUI / 任务 / CLI 三合一）
    gui.py             tkinter 控制台界面（科技风仪表盘）
    taskmod.py         登录计划任务（LanRouteFixer）的安装与移除
    lanrf.ico          GUI 与 exe 的图标
    build-exe.cmd      构建命令行单文件 exe
    build-gui.cmd      构建 GUI 单文件 exe
    probe_winapi.py    只读探针（核对结构体尺寸与真实选路）
    README.md          Windows 工具的使用说明
src/usr/bin/lan-route-fixer                    入口（CLI / GUI 分发）
src/usr/lib/lan-route-fixer/app.py             GTK4 / libadwaita 界面（侧栏单窗口）
src/usr/lib/lan-route-fixer/core.py            兼容层（保留 2.0.x 的 core.* 名字）
src/usr/lib/lan-route-fixer/lanrf/             可复用实现
    model.py        纯数据模型（目标、路由条目、proto 标记）
    targets.py      目标解析与校验
    config.py       配置读写 + 状态发布 + 发现缓存路径
    backends.py     平台后端协议与选择
    linux.py        Linux 后端（ip / sysfs / 路由与规则解析）
    windows.py      Windows 后端（iphlpapi / netioapi，ctypes）
    winapi.py       Windows IP Helper API 的 ctypes 绑定与结构体
    sshconfig.py    OpenSSH 客户端配置解析（import-ssh 用）
    netlink.py      rtnetlink 事件订阅
    routing.py      网卡选择策略
    reconcile.py    纯协调引擎（检查 → 计划 → 执行 → 复核）
    checks.py       只读状态检查
    discovery.py    局域网邻居发现
    cleanup.py      垃圾回收（残留路由/规则 + 僵尸目标），CLI 与 GUI 共用
    privileged.py   提权边界客户端（pkexec）
    helper.py       提权边界内部（校验 + 改内核）
    system.py       多配置文件协调（systemd / dispatcher）
    daemon.py       事件驱动修复循环（select 模式 + GLib/D-Bus 模式）
    tui.py          全屏终端控制台（纯标准库，Windows 终端也能跑）
    dbus.py         控制接口（服务端 + 客户端，失败即降级）
    doctor.py       诊断
    cli.py          命令行
src/usr/libexec/lan-route-fixer/                特权 helper 与 root 一次性修复
src/usr/share/dbus-1/system.d/                  D-Bus 访问控制（只有 root 能注册名字）
src/usr/share/dbus-1/system-services/           D-Bus 激活（GUI 调用时自动拉起守护进程）
docs/screenshots/                               README 使用的界面截图（tools/gui-screenshot 生成）
tools/verify-install                            真机验证（需要 root）
tools/verify-namespace                          真实内核验证（无需 root，26 项检查）
tools/gui-smoke                                 GTK 控件树冒烟测试（无需人点击）
tools/gui-screenshot                            把每一页渲染成 PNG
tools/plan-preview                              只读预览将要执行的 ip 命令
tests/                                          单元测试（含假后端）
```

## Windows

Windows 上的失败模式和 Linux 一样，只是内核接口不同：aTrust 连上后，会把
`10/8`、`172.16/12`、`192.168/16` 拆成 `/25`…`/32` 的 NetMgmt 路由塞进它的隧道
网卡，metric 全是 0。Windows **只有一张路由表**，也没有 `ip rule`，所以这里不用
策略路由，而是用「更长前缀」：

- 给每台目标主机装一条 `/32` 主机路由，下一跳 `0.0.0.0`（on-link）、metric 0，
  装在物理网卡上。aTrust 的 `/26`、`/25` 再快也赢不过更长前缀。
- Windows 没有 rtnetlink 事件源（`NotifyRouteChange2` 还没有接入），守护进程
  自动退回轮询（默认 10 秒）。aTrust 重连后，最迟一个轮询周期恢复。
- 写路由表必须有管理员权限：未提权时 `fix` 直接报错，不会反复弹 UAC。

### 用法

只想马上修好、不装 Python？双击 `windows\fix-lan.cmd` 即可（自动请求
管理员权限，写完 `/32` 路由再显示状态）。它的 `status` / `apply` / `remove` /
`watch` / `install` 子命令见 [windows/README.md](windows/README.md)。

用项目自带 CLI 的话：

```powershell
# 1) 不需要管理员：看每台主机现在到底走哪块网卡
python -B src\usr\bin\lan-route-fixer status

# 2) 从 OpenSSH 配置导入局域网主机（先预演，再写入）
python -B src\usr\bin\lan-route-fixer import-ssh --dry-run
python -B src\usr\bin\lan-route-fixer import-ssh --yes

# 3) 管理员 PowerShell：真正写入 /32 主机路由
python -B src\usr\bin\lan-route-fixer fix

# 4) 常驻：轮询修复（管理员），或只在前台观察
python -B src\usr\bin\lan-route-fixer run --interval 10

# 5) 诊断
python -B src\usr\bin\lan-route-fixer doctor
```

`windows/pin-lan.ps1` 是不需要 Python 的等价实现
（`status` / `apply` / `remove` / `watch` / `install`），用法见
[windows/README.md](windows/README.md)。

### 可执行文件（Release 附件）

[GitHub Releases](https://github.com/pychen117/lan-route-fixer/releases) 里的
`lan-route-fixer.exe` 是 PyInstaller 打包的单文件控制台程序，不需要装 Python：

```powershell
lan-route-fixer.exe status            # 只看，不需要管理员
lan-route-fixer.exe import-ssh --dry-run
lan-route-fixer.exe fix               # 管理员 PowerShell
lan-route-fixer.exe run --interval 10 # 管理员：常驻轮询修复
lan-route-fixer.exe doctor
```

自己构建：双击 `windows\build-exe.cmd`（需要 Python 3.10+，脚本会按需装
PyInstaller），产物在 `dist\windows\lan-route-fixer.exe`。onefile 版启动时会解压
到 `%TEMP%`；如果那台机器的临时目录被安全策略锁死，把构建命令里的 `--onefile`
换成 `--onedir`。

### 图形界面

同一个 Release 里还有 `lan-route-fixer-gui.exe`：双击直接打开控制台界面，
不用记命令。界面是深色「雷达」风格，实时显示每台 SSH 主机到底走物理网卡还是
被 aTrust 的隧道接管，并提供：

- **SCAN**：重新读取路由表与网卡状态（F5 同效）；
- **FIX ROUTES**：写入 `/32` 主机路由；未提权时自动通过 UAC 重新启动自己；
- **IMPORT SSH**：从 `~/.ssh/config` 预览并导入局域网主机；
- **DIAGNOSE**：运行 `doctor` 的诊断项并在对话框里展示；
- **WATCHDOG**：注册/移除登录计划任务（以管理员身份运行
  `lan-route-fixer-gui.exe run --interval 10`），aTrust 重连后自动补回路由。

```powershell
lan-route-fixer-gui.exe            # 打开界面
lan-route-fixer-gui.exe --version  # 仍然是同一个二进制
lan-route-fixer-gui.exe status     # 命令行模式完全可用
```

自己构建：双击 `windows\build-gui.cmd`，产物在
`dist\windows\lan-route-fixer-gui.exe`（窗口程序，没有控制台；CLI 模式下的输出
仍然有效，只是不显示在窗口里）。

### 路径

| 内容 | Windows 路径 |
| --- | --- |
| 用户配置 | `%APPDATA%\lan-route-fixer\config.json` |
| 系统配置 | `%PROGRAMDATA%\lan-route-fixer\config.json`（`LAN_ROUTE_FIXER_SYSTEM_CONFIG` 可覆盖） |
| 状态 | `%LOCALAPPDATA%\lan-route-fixer\state.json`（`LAN_ROUTE_FIXER_STATE` 可覆盖） |

`routing_mode` 在 Windows 上应保持 `main`；填 `rule` 时后端会说明这里只有一张
路由表，`ensure_rule` / `remove_rule` 会抛出 `NotImplementedError`。

### 实现映射

| Linux | Windows（iphlpapi / netioapi） |
| --- | --- |
| `ip route show` | `GetIpForwardTable2` + `FreeMibTable` |
| `ip route replace` | `CreateIpForwardEntry2`，条目已存在时回退 `SetIpForwardEntry2` |
| `ip route del` | `DeleteIpForwardEntry2` |
| `ip route get` | `GetBestRoute2` |
| `/sys/class/net`、`ip -d link` | `GetAdaptersAddresses`（ifIndex + FriendlyName + IfType/OperStatus） |
| `ip -o addr show` | `GetAdaptersAddresses` 的地址链表 / `GetUnicastIpAddressTable` |
| rtnetlink socket | `NotifyRouteChange2`（尚未接入，改用轮询） |
| `ip rule`（策略路由） | 无对应物，`supports_policy_rules = False` |
| pkexec / polkit | 管理员 PowerShell / UAC（没有 LocalSystem 服务与具名管道） |
| D-Bus 系统总线 | 尚未移植；GUI 与 D-Bus 守护仍要求 Linux |

两个踩过的坑已经写进 `lanrf/winapi.py` 的断言里：

- `SOCKADDR_INET` 是 union，成员里有 `ULONG`，对齐是 **4** 而不是 2。把它写成
  `(c_ushort, c_ubyte*26)` 会让 `IP_ADDRESS_PREFIX` 变成 30 字节而不是 32，之后
  每个字段都错 2 字节（metric 读成 3600、NextHop 的 family 读成 0、LUID 是垃圾）。
- `GetIpForwardTable2` 返回的缓冲区前面有一个 `ULONG NumEntries`，行数据从
  `ptr+8` 开始，`MIB_IPFORWARD_ROW2` 必须是 104 字节。

### 还没做的

`NotifyRouteChange2` 事件源、LocalSystem 服务 + 具名管道（现在的后台方式只有
「管理员前台 `run`」和「登录计划任务」）、Windows 安装包、GUI。`prune` 依赖
`owned` 启发式（主机路由 + metric 0 + on-link），因为 Windows 的路由行没有地方
写 `proto 66`。

## 开发

```sh
# 跑测试
python3 -m unittest discover -s tests -t .

# 不装到系统也能跑源码树（入口会自动找同目录的 ../lib/lan-route-fixer，
# 所以 Windows 上也不必先设 LAN_ROUTE_FIXER_LIB）
python3 src/usr/bin/lan-route-fixer doctor

# Windows：解释器用 python -B（防止在仓库里写 __pycache__），
# 且本机没有可写临时目录时，测试会卡在 tests/__init__.py 的 tempfile.mkdtemp；
# 给一个可写目录即可：
set TMPDIR=%USERPROFILE%\AppData\Local\Temp
python -B -m unittest discover -s tests -t .
```

便于测试的环境变量：`LAN_ROUTE_FIXER_LIB`、`LAN_ROUTE_FIXER_HELPER`、
`LAN_ROUTE_FIXER_PKEXEC`、`LAN_ROUTE_FIXER_IP`、`LAN_ROUTE_FIXER_STATE`、
`LAN_ROUTE_FIXER_SYSTEM_CONFIG`。
