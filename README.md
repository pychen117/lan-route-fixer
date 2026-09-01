# lan-route-fixer

把选中的局域网设备“钉”在物理网卡上，避免 VPN 全隧道抢走私网路由后设备失联。

典型场景：

- Deskflow / Synergy / Barrier / Input Leap 键鼠共享
- RDP / VNC / Sunshine 等远程桌面
- NAS / SMB / NFS 文件共享
- 打印机、IP 摄像头、IPMI/BMC、智能家居设备
- 内网 GitLab、数据库、开发服务器、树莓派

## 原理

很多 VPN（例如 aTrust、部分企业客户端）会启用 full-tunnel，把整个
`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 都塞进隧道。于是发往同网段
设备（比如 `192.168.4.169`）的包也进了 `utun7`，永远到不了目标。

本工具给每个目标加一条更长前缀的路由：

```sh
ip route replace 192.168.4.169/32 dev wlp0s20f3
```

最长前缀匹配会优先于 VPN 的 `/24`，把流量拉回物理网卡。`route replace`
是幂等的，重复执行安全。

## 功能

- 自动扫描局域网设备（ARP 邻居表 + mDNS 反向解析）
- 自动探测不同电脑上的物理网卡（基于 link type 和 `/sys/class/net`）
- 支持私有 IPv4 地址/网段，以及 IPv6 ULA / 链路本地地址
- 手动或自动选择目标网卡；自动按目标网段匹配同网段网卡
- GUI（GTK4/libadwaita）和 CLI 两种使用方式
- CLI 目标管理：`list` / `add` / `remove` / `enable` / `disable` / `set-interface`
- 批量修复，一次授权处理全部目标
- PolicyKit 特权 helper，仅允许修改私有/本地路由到非隧道网卡
- 用户级开机自启，以及系统级 systemd timer + NetworkManager dispatcher

## 安装

从源码构建 `.deb`：

```sh
cd lan-route-fixer
dpkg-buildpackage -us -uc -b
sudo apt install ../lan-route-fixer_2.0.3-1_all.deb
```

安装后：

- GUI：应用菜单打开“局域网路由修复”
- CLI：`lan-route-fixer scan|check|fix|list|add|remove|enable|disable|set-interface`

## CLI 用法

```sh
# 扫描当前局域网邻居（JSON）
lan-route-fixer scan

# 查看当前配置
lan-route-fixer list

# 添加并启用目标；网卡留空则自动选择
lan-route-fixer add 192.168.4.169 --name "Windows 台式机"
lan-route-fixer add 192.168.8.0/24 --name "NAS 网段" --interface eth0

# 查看/检查/修复
lan-route-fixer check
lan-route-fixer fix

# 修改目标
lan-route-fixer set-interface 192.168.4.169 auto
lan-route-fixer disable 192.168.4.169
lan-route-fixer enable 192.168.4.169
lan-route-fixer remove "Windows 台式机"

# 前台循环监控（适合调试）
lan-route-fixer run

# 使用自定义配置，例如系统级/无头配置
sudo mkdir -p /etc/lan-route-fixer
sudo lan-route-fixer --config /etc/lan-route-fixer/config.json add 192.168.4.169
```

## 路由持久化

除了应用内的定时检查，还提供两个系统级兜底：

### NetworkManager dispatcher

网络接口或 VPN 状态变化时立即重放路由：

```sh
/etc/NetworkManager/dispatcher.d/90-lan-route-fixer
```

### systemd service + timer

无 GUI 环境下，每 30 秒检查一次全部用户配置和
`/etc/lan-route-fixer/config.json`，并修复错误路由：

```sh
systemctl status lan-route-fixer.timer
systemctl list-timers lan-route-fixer.timer
```

安装 `.deb` 后由 `dh_installsystemd` 自动启用；如需手动关闭：

```sh
sudo systemctl disable --now lan-route-fixer.timer
```

系统级后台修复会尊重每个配置文件的 `auto_fix` 设置。若某配置为
`"auto_fix": false`，systemd 和 dispatcher 只检查该配置，不会自动改路由。

## 配置

默认用户配置路径：`~/.config/lan-route-fixer/config.json`

系统级/无头配置路径：`/etc/lan-route-fixer/config.json`

```json
{
  "targets": [
    {
      "name": "Windows 台式机",
      "address": "192.168.4.169/32",
      "interface": "",
      "enabled": true
    },
    {
      "name": "NAS 网段",
      "address": "192.168.8.0/24",
      "interface": "eth0",
      "enabled": true
    }
  ],
  "interval_seconds": 30,
  "auto_fix": true,
  "autostart": false
}
```

`interface` 留空表示自动选择：优先选和目标同网段的网卡，否则选默认出口。

## 开发

```sh
# 运行测试
python3 -m unittest discover -s tests
```

核心逻辑与 GUI 分离：`src/usr/lib/lan-route-fixer/core.py` 不含 GTK 依赖，
可以被 CLI 和测试直接使用。
