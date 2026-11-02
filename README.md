# DNS 泄漏检测脚本

一键检测你的代理（小火箭 / Clash Verge Rev / v2rayN 等）有没有 **DNS 泄漏**。

- 只需要 Python 3，**不用装任何第三方库**
- 支持 **macOS / Windows / Linux**
- 不只看检测网站的结果，还会检查**本机系统 DNS 是否真的被代理接管**，能识别网页检测站看不出来的泄漏

> 由 [H云端实验室](https://www.youtube.com/@hcloudlab) 制作，配套视频讲解见频道。

---

## 一、下载

点击本页面上方的 `dns_leak_test.py` → 右上角 **Download raw file**（下载图标），保存到「下载」文件夹。

或者在终端里（需要先开代理）：

```bash
curl -O https://raw.githubusercontent.com/hcloudlab/dns-leak-test/main/dns_leak_test.py
```

## 二、运行

先打开终端，进入脚本所在的文件夹：

```bash
cd ~/Downloads
```

> Windows 用户：打开 PowerShell，输入 `cd $HOME\Downloads`，下面命令里的 `python3` 改成 `python`。

**最常用：直接运行**（检测 TUN / 虚拟网卡模式，以及系统 DNS）

```bash
python3 dns_leak_test.py
```

**只开了系统代理时**，加上你客户端的 HTTP 端口：

```bash
python3 dns_leak_test.py --proxy http://127.0.0.1:7897
```

| 客户端 | 常见默认端口 |
|---|---|
| 小火箭（macOS） | 1082 |
| Clash Verge Rev | 7897 |
| v2rayN | 10808 |

端口以你客户端设置里显示的为准。

> ⚠️ 一次只复制一行命令运行。不要把带 `#` 的说明文字一起粘进终端。

## 三、看懂结果

结果分三部分：

**1. 出口 IP**：应该是你的 VPS / 节点的 IP。如果显示国内 IP，说明代理根本没生效。

**2. 查询过测试域名的 DNS 服务器**：标红 `[本地/国内]` 的就是泄漏。全是 Cloudflare / Google 等境外 DNS 是正常的（那是 VPS 的上游 DNS）。

**3. 本机系统 DNS**（最关键）：

| 显示 | 含义 |
|---|---|
| 🟢 代理软件接管 / 查询被代理劫持 | 正常，系统 DNS 查询走了代理 |
| 🟡 境外公共 DNS，但从本机明文直连 | **泄漏**：虽然是 1.1.1.1 这类境外 DNS，但运营商能看到你查了什么 |
| 🔴 国内公共 DNS / 路由器 DNS | **泄漏** |

> 为什么要看第 3 项？我们实测发现：TUN 开和关两种状态下，检测网站记录到的 DNS 可能**一模一样**（都是 Cloudflare），网页检测根本分不出来。只有检查系统 DNS 的查询到底从哪儿发出去，才能判断。

**最后一行 `bash.ws 原始判定：DNS may be leaking`** 可以忽略。检测站只要发现 DNS 和出口 IP 不是同一家运营商就会这样提示，以脚本给出的「结论」为准。

## 四、发现泄漏怎么修

最有效的方法：**开启 TUN / 虚拟网卡模式**，并确认开启了 DNS 劫持。

| 客户端 | 设置 |
|---|---|
| Clash Verge Rev | 开启「虚拟网卡模式」，DNS 劫持填 `any:53` |
| v2rayN | 开启 TUN 模式 |
| 小火箭（macOS） | 「兼容模式」保持关闭 |

修好后重新运行脚本，系统 DNS 显示为绿色即可。

其他常见原因：

- 分流规则里 `GEOIP` / `IP-CIDR` 没加 `no-resolve`
- Mihomo 的 `nameserver` 用了国内 DNS，又没配置 `nameserver-policy`
- 浏览器开启了「安全 DNS（DoH）」并指向国内 DoH

## 五、实测结果（macOS）

| 客户端 | 只开系统代理 | 开启 TUN |
|---|---|---|
| 小火箭 | 不泄漏（兼容模式开关都会接管 DNS） | 不泄漏 |
| Clash Verge Rev | **泄漏** | 不泄漏（fake-ip） |
| v2rayN | **泄漏** | 不泄漏（真实 IP 模式） |

## 六、其他参数

```bash
python3 dns_leak_test.py --mode system      # 只测系统 DNS
python3 dns_leak_test.py --mode proxy       # 只测走代理的请求
python3 dns_leak_test.py --count 20         # 多测几个域名
python3 dns_leak_test.py --json             # 输出原始数据
python3 dns_leak_test.py --local-country China   # 本地所在国家（英文），默认 China
```

## 注意事项

- 请在**你自己的电脑**上运行，不是在 VPS 上运行
- TUN 关闭时，结果里可能会显示你的**真实宽带 IP**，截图分享前记得打码
- 检测使用 [bash.ws](https://bash.ws) 的公共接口和 Cloudflare 的 `whoami.cloudflare` 查询，不会收集或上传其他数据

## 工作原理（给想深入了解的人）

1. 向 bash.ws 申请一个唯一 ID，然后查询一批随机子域名 `xxx.<ID>.bash.ws`。这些域名只有 bash.ws 的权威 DNS 能回答，所以谁来查询，它就能记录下谁
2. 读取本机系统 DNS，并对每一个直接发查询验证：
   - 返回 `198.18.x.x`（fake-ip）→ 被代理劫持（Clash、小火箭）
   - 否则询问 Cloudflare `whoami`：查询来源 = 代理出口 IP → 被劫持（v2rayN 等）；来源是你的本地 IP → 直连发出，泄漏

## License

MIT
