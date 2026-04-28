# cfnat

一个轻量级 Cloudflare IP 扫描 + TCP 转发工具。

---

## 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [工作原理](#工作原理)
- [快速开始](#快速开始)
- [常用参数说明](#常用参数说明)
- [使用示例](#使用示例)
- [日志说明](#日志说明)
- [内存优化](#内存优化)
- [构建方式](#构建方式)
- [GitHub Actions](#github-actions)
- [常见问题](#常见问题)
- [免责声明](#免责声明)

---

## 项目简介

cfnat 是一个轻量级 Cloudflare IP 扫描与 TCP 转发工具。

本项目修改自 **CF中转群主的 cfnat-origin**，在原有思路基础上增强了单端口转发、TLS / 非 TLS 自动识别、健康检查、日志控制和低内存运行。

cfnat 用于：

- 扫描 Cloudflare IP
- 按延迟筛选优质节点
- 自动选择可用 IP
- 提供单端口 TCP 转发（同时支持 TLS 和非 TLS）

👉 特点是：**本地只需要一个端口**

---

## 核心特性

- 支持 IPv4 / IPv6 扫描
- 支持按 Cloudflare 数据中心筛选（HKG / SJC / LAX 等）
- 自动延迟排序
- 自动健康检查 + IP 切换
- 单端口同时支持 TLS / 非 TLS
- 自动协议识别（无需配置）
- 低日志噪音设计
- 支持详细调试模式
- 针对路由器低内存优化

---

## 工作原理

cfnat 的核心目标是：**本地只监听一个端口，但同时承接 TLS 和非 TLS 流量，并自动转发到合适的 Cloudflare 目标端口。**

### 整体链路

```text
客户端
  ↓
本地监听端口（-addr，例如 0.0.0.0:40000）
  ↓
cfnat 自动识别连接类型
  ↓
Cloudflare 优选 IP
```

### 单端口分流逻辑

客户端只需要连接同一个本地端口，例如：

```text
服务器IP:40000
```

cfnat 收到连接后，会读取客户端发来的首个数据字节，用来判断连接类型：

```text
首字节是 0x16  → 认为是 TLS 流量
其他情况       → 认为是非 TLS / HTTP 流量
```

然后按不同协议转发到不同的 Cloudflare 目标端口：

```text
TLS 流量
  客户端 → 本地端口 → cfnat → Cloudflare IP:443

非 TLS / HTTP 流量
  客户端 → 本地端口 → cfnat → Cloudflare IP:80
```

### 为什么本地一个端口就够

`-addr` 是本地监听地址，例如：

```bash
-addr=0.0.0.0:40000
```

它决定用户、客户端、sing-box、xray、浏览器或其他程序连接哪个本地端口。

`-port` 和 `-http-port` 是远端 Cloudflare 目标端口：

```bash
-port 443
-http-port 80
```

两者职责不同：

```text
-addr       = 本机对外开放的入口
-port       = TLS 流量转发到 Cloudflare 的目标端口
-http-port  = 非 TLS 流量转发到 Cloudflare 的目标端口
```

也就是说，用户侧只看到一个端口，cfnat 内部负责自动判断和转发。

### 可用 IP 检测原理

cfnat 的 IP 检测不是简单判断某个 IP 能不能 ping 通，而是按“可连接、可识别、可筛选、可转发”的顺序逐步筛选。

#### 1. 获取 IP 段

程序会先读取本地文件：

```text
ips-v4.txt
ips-v6.txt
```

如果文件不存在，则会自动从远程地址下载对应的 Cloudflare IP 段。

#### 2. 生成待测 IP

根据参数决定如何生成待测 IP：

```text
-random=true   从每个 CIDR 中随机抽取 IP
-random=false  将 CIDR 拆分为完整 IP 列表逐个测试
```

IPv4 / IPv6 由 `-ips` 控制：

```text
-ips=4  使用 IPv4
-ips=6  使用 IPv6
```

#### 3. TCP 连通性测试

对每个待测 IP，程序会先尝试连接 Cloudflare HTTP 端口：

```text
IP:80
```

这个阶段主要判断：

```text
当前网络到这个 Cloudflare IP 是否可达
TCP 建连耗时是多少
```

连接耗时会被记录为该 IP 的基础延迟。

#### 4. 通过 CF-RAY 识别机房

TCP 连通后，程序会向该 IP 发起 HTTP 请求，并从响应头里读取：

```text
CF-RAY
```

Cloudflare 的 `CF-RAY` 响应头通常会带有数据中心代号，例如：

```text
xxxx-HKG
xxxx-SJC
xxxx-LAX
```

程序会提取最后的机房代码，并结合 `locations.json` 显示地区、城市等信息。

#### 5. 按 colo 过滤

如果用户指定了：

```bash
-colo=HKG
```

程序只保留 `CF-RAY` 识别为 `HKG` 的 IP。

也可以指定多个：

```bash
-colo=HKG,SJC,LAX
```

不符合指定机房的 IP 会被丢弃。

#### 6. 按延迟排序

通过机房过滤后，程序会按 TCP 建连耗时从低到高排序。

例如：

```text
17 ms
18 ms
20 ms
25 ms
```

延迟越低，排序越靠前。

#### 7. 保留候选 IP

排序完成后，只保留前 `-ipnum` 个 IP。

默认：

```text
-ipnum=20
```

这些 IP 会进入候选池，后续用于健康检查和自动切换。

#### 8. 健康检查

候选 IP 还需要通过健康检查才能成为当前转发 IP。

当前版本使用 HTTPS 目标端口作为主要健康探针：

```text
Cloudflare IP:443
```

程序会使用 `-domain` 指定的域名和路径发起 HTTPS 请求，例如默认：

```text
https://cloudflaremirrors.com/debian
```

并检查返回状态码是否等于 `-code`，默认是：

```text
200
```

只有状态码符合预期的 IP，才会被认为是当前可用 IP。

#### 9. 自动切换

运行过程中，程序会定期复查当前 IP。

如果当前 IP 连续失败，程序会从候选池中继续寻找下一个通过健康检查的 IP，并自动切换。

```text
当前 IP 暂不可用
  ↓
连续失败达到阈值
  ↓
检查候选池下一个 IP
  ↓
切换到新的可用 IP
```

#### 为什么健康检查主要测 443

程序运行时虽然同时支持 TLS 和非 TLS 流量，但 Cloudflare 的 HTTPS 端口通常更适合作为稳定性探针。

实际使用中，能稳定通过 `443` 健康检查的 Cloudflare IP，通常也能满足本工具的单端口自动分流使用场景。

运行时转发仍然是：

```text
TLS 流量      → Cloudflare IP:443
非 TLS 流量   → Cloudflare IP:80
```

### 自动切换 IP

运行过程中，cfnat 会定期检查当前 IP 是否可用。

如果当前 IP 连续失败，会自动切换到候选列表中的下一个可用 IP：

```text
当前 IP 暂不可用
  ↓
连续失败达到阈值
  ↓
切换到下一个可用 IP
  ↓
继续转发
```

这个过程不需要用户手动干预。

### 数据转发方式

cfnat 不解密 TLS，不修改 HTTP 内容，也不主动理解业务协议。

它只做 TCP 层转发：

```text
客户端发什么字节 → cfnat 原样转发给 Cloudflare IP
Cloudflare 返回什么字节 → cfnat 原样返回给客户端
```

因此它更接近一个轻量级 TCP 中转器，而不是 HTTP 反向代理。

---

## 快速开始

### Linux（示例）

```bash
chmod +x cfnat-linux-amd64
./cfnat-linux-amd64 -addr=0.0.0.0:40000 -colo=HKG -delay=50 -random=false
```

访问：

```
服务器IP:40000
```

---

## 常用参数说明

| 参数 | 说明 |
|-----|------|
| `-addr` | 本地监听地址 |
| `-colo` | 数据中心筛选 |
| `-delay` | 最大延迟（毫秒） |
| `-ipnum` | 保留 IP 数量 |
| `-num` | 每次连接并发数 |
| `-port` | TLS 目标端口（默认 443） |
| `-http-port` | 非 TLS 端口（默认 80） |
| `-random` | 是否随机 IP |
| `-task` | 扫描并发 |
| `-verbose` | 详细日志 |
| `-log-conn` | 连接日志 |

---

## 使用示例

### 香港节点

```bash
./cfnat-linux-arm64 -addr=0.0.0.0:40000 -colo=HKG -delay=80 -random=false
```

### 多地区

```bash
-colo=HKG,SJC,LAX
```

### 调试模式

```bash
-verbose=true -log-conn=true
```

---

## 日志说明

正常：

```
可用 IP: 104.18.x.x
状态检查成功
```

异常：

```
状态检查失败 (1/2): 当前 IP 暂不可用
切换到新的 IP
```

---

## 内存优化

cfnat 针对路由器、OpenWrt、ImmortalWrt 等低内存环境做了运行时优化：

- 使用 `sync.Pool` 复用数据转发 buffer，减少高并发连接下的重复分配
- 使用 `io.CopyBuffer` 进行 TCP 双向转发，避免每条连接都临时申请新 buffer
- 不保存每条候选连接的完整列表，只保留当前最佳连接
- 默认降低日志输出，减少大量字符串格式化带来的内存和 CPU 开销
- 在代码内部固定设置 `debug.SetGCPercent(75)`，让 Go GC 比默认值更积极，降低长期运行时的内存占用

`GCPercent` 不作为命令行参数暴露，避免用户误调导致 CPU 占用升高或运行表现不稳定。

---

## 构建方式

```bash
go build -o cfnat ./cfnat.go
```

交叉编译：

```bash
GOOS=linux GOARCH=arm64 go build -o cfnat-linux-arm64
```

---

## GitHub Actions

支持：

- Linux / macOS / Windows / BSD
- arm / arm64 / amd64 / mips / riscv / s390x

并自动：

- 编译所有架构

---

## 常见问题

### 权限错误

```bash
chmod +x cfnat-linux-arm64
```

### 没有可用 IP

- 放宽 `-delay`
- 换 `-colo`
- 开 `-verbose` 排查

---

## 免责声明

本工具仅用于网络测试与学习用途。

请在合法环境下使用。