#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNS 泄漏检测脚本（基于 bash.ws 公共接口）

原理：
  1. 向 bash.ws 申请一个唯一 ID
  2. 解析 / 访问若干个随机子域名  <随机串>.<ID>.bash.ws
     这些子域名只能由 bash.ws 的权威 DNS 应答，所以谁来查询，它就能记录下谁
  3. 取回记录：哪些 DNS 服务器查询过这些域名 + 你的出口 IP
  4. 判断：如果出现国内运营商 / 本地所在国家的 DNS，说明域名查询绕过了代理 = DNS 泄漏

两种触发方式（默认 both 都做）：
  system  : 走系统解析器（检测操作系统 DNS 是否泄漏，TUN / 透明代理场景重点看这个）
  proxy   : 通过代理发 HTTP 请求，让代理链去解析（检测代理客户端本身的分流 / DNS 配置）

用法示例：
  # TUN 模式 / 全局透明代理：直接运行
  python3 dns_leak_test.py

  # 系统代理模式（Clash Verge Rev 混合端口，按自己的端口改）
  python3 dns_leak_test.py --proxy http://127.0.0.1:7890

  # 多测几轮、指定本地国家
  python3 dns_leak_test.py --count 20 --local-country China

注意：请在「客户端电脑」上运行，而不是在 VPS 上运行。
"""

import argparse
import concurrent.futures
import json
import random
import socket
import string
import sys
import urllib.request

API_HOST = "bash.ws"

# 常见国内运营商 / 云厂商 ASN 关键词（命中即视为国内 DNS）
CN_ASN_KEYWORDS = (
    "chinanet", "china telecom", "china unicom", "unicom", "china mobile",
    "cmnet", "cernet", "china broadband", "tencent", "alibaba", "aliyun",
    "baidu", "huawei cloud", "dr.peng", "great wall broadband",
)

# 终端颜色（Windows 新终端也支持）
RED, YELLOW, GREEN, CYAN, BOLD, RESET = (
    "\033[31m", "\033[33m", "\033[32m", "\033[36m", "\033[1m", "\033[0m"
)


def color(text, c):
    return f"{c}{text}{RESET}" if sys.stdout.isatty() else text


def build_opener(proxy):
    if proxy:
        if proxy.lower().startswith("socks"):
            sys.exit("本脚本不依赖第三方库，只支持 HTTP 代理。"
                     "Clash/Mihomo 的混合端口（如 7890）同时支持 HTTP，请用 http://127.0.0.1:端口")
        handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    else:
        handler = urllib.request.ProxyHandler()  # 自动读取环境变量 / 系统代理
    return urllib.request.build_opener(handler)


# ---------------- 本地系统 DNS 检查 ----------------
import ipaddress
import platform
import re
import subprocess

CN_PUBLIC_DNS = {
    "114.114.114.114", "114.114.115.115", "223.5.5.5", "223.6.6.6",
    "119.29.29.29", "182.254.116.116", "180.76.76.76", "1.2.4.8", "210.2.4.8",
    "101.226.4.6", "218.30.118.6", "117.50.10.10", "52.80.52.52",
}
# 代理软件接管 DNS 时常见的地址：fake-ip 段、回环
PROXY_DNS_NETS = [ipaddress.ip_network(n) for n in
                  ("198.18.0.0/15", "127.0.0.0/8", "::1/128", "fdfe:dcba:9876::/48")]


def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout
    except Exception:
        return ""


def _ips(text):
    out = []
    for tok in re.findall(r"[0-9a-fA-F:.]+", text):
        try:
            out.append(str(ipaddress.ip_address(tok.strip("."))))
        except ValueError:
            pass
    return out


def get_system_dns():
    system = platform.system()
    servers = []
    if system == "Darwin":
        # 只取不带 domain 的 resolver（默认解析器），忽略 mdns / 特定域
        for block in _run(["scutil", "--dns"]).split("resolver #"):
            if "domain" in block or "nameserver" not in block:
                continue
            servers += _ips(" ".join(re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", block)))
            if servers:
                break
    elif system == "Linux":
        try:
            with open("/etc/resolv.conf") as f:
                servers = _ips(" ".join(re.findall(r"^\s*nameserver\s+(\S+)", f.read(), re.M)))
        except Exception:
            pass
        if servers and all(s.startswith("127.0.0.5") for s in servers):  # systemd-resolved
            real = _ips(" ".join(re.findall(r":\s*(.+)", _run(["resolvectl", "dns"]))))
            servers = real or servers
    elif system == "Windows":
        servers = _ips(_run(["powershell", "-NoProfile", "-Command",
                             "Get-DnsClientServerAddress | Select -Expand ServerAddresses"]))
    seen, uniq = set(), []
    for s in servers:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def classify_dns(ip):
    addr = ipaddress.ip_address(ip)
    if any(addr in n for n in PROXY_DNS_NETS):
        return "proxy", "代理软件接管（fake-ip / 本地）"
    if ip in CN_PUBLIC_DNS:
        return "cn", "国内公共 DNS"
    if addr.is_private or addr.is_link_local:
        return "lan", "路由器 / 局域网 DNS（通常转发给运营商）"
    return "plain", "境外公共 DNS，但从本机明文直连"


FAKE_IP_NET = ipaddress.ip_network("198.18.0.0/15")


def probe_dns(server, qname, timeout=3, qtype=1, qclass=1):
    """直接向 server 发一个查询。返回应答记录列表（A 记录为 IP 字符串，TXT 为文本）；无应答返回 None"""
    import struct
    tid = random.randint(0, 0xFFFF)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for label in qname.strip(".").split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", qtype, qclass)
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    try:
        with socket.socket(fam, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(q, (server, 53))
            resp, _ = s.recvfrom(4096)
    except Exception:
        return None
    try:
        an = struct.unpack(">H", resp[6:8])[0]
        i = 12
        while resp[i] != 0:  # 跳过问题区域名
            i += resp[i] + 1
        i += 5
        out = []
        for _ in range(an):
            if resp[i] & 0xC0 == 0xC0:
                i += 2
            else:
                while resp[i] != 0:
                    i += resp[i] + 1
                i += 1
            rtype, _, _, rdlen = struct.unpack(">HHIH", resp[i:i + 10])
            i += 10
            rdata = resp[i:i + rdlen]
            if rtype == 1 and rdlen == 4:
                out.append(socket.inet_ntoa(rdata))
            elif rtype == 16:
                j, txt = 0, ""
                while j < len(rdata):
                    n = rdata[j]
                    txt += rdata[j + 1:j + 1 + n].decode(errors="replace")
                    j += n + 1
                out.append(txt)
            i += rdlen
        return out
    except Exception:
        return []


def whoami_via(server):
    """向 server 询问 Cloudflare 的 whoami：返回「这个查询最终是从哪个 IP 发到 Cloudflare 的」。

    - 查询被代理劫持并从 VPS 转发 → 返回 VPS 出口 IP
    - 查询从本机直连 Cloudflare → 返回你的本地宽带 IP
    - server 不是 Cloudflare 且没被劫持 → 一般无结果
    """
    res = probe_dns(server, "whoami.cloudflare", qtype=16, qclass=3)  # TXT / CH
    if not res:
        return None
    for r in res:
        try:
            return str(ipaddress.ip_address(r.strip().strip('"')))
        except ValueError:
            continue
    return None


def check_system_dns(exit_ips=()):
    """返回 (是否有问题, 列表)；拿不到系统 DNS 时返回 (None, [])

    只看地址不够：
    - Clash Verge Rev 开 TUN 时会把系统 DNS 设成 114.114.114.114 之类的占位地址，查询其实被劫持；
      这种情况探测会拿回 198.18.x.x 的 fake-ip。
    - v2rayN（sing-box）开 TUN 不改系统 DNS，劫持后返回真实 IP，fake-ip 判断失效；
      这种情况用 Cloudflare whoami 看查询最终从哪个 IP 发出：等于代理出口 IP 就是被劫持了。
    """
    servers = get_system_dns()
    if not servers:
        return None, []
    exit_ips = set(exit_ips)
    result = []
    for s in servers:
        kind, desc = classify_dns(s)
        if kind != "proxy":
            ips = probe_dns(s, f"{rand_label()}.example.com")
            if ips is None:
                ips = probe_dns(s, "www.apple.com")
            if ips and all(_is_fake(i) for i in ips):
                kind, desc = "hijack", "查询被代理劫持（返回 fake-ip），实际未发给该地址"
            else:
                who = whoami_via(s)
                if who and who in exit_ips:
                    kind, desc = "hijack", f"查询被代理劫持（Cloudflare 看到的来源 = 代理出口 {who}）"
                elif who and exit_ips:
                    desc += f"（Cloudflare 看到的来源是 {who}，不是代理出口 → 查询直连发出）"
                elif who:
                    desc += f"（Cloudflare 看到的来源是 {who}，无出口 IP 可比对）"
                elif ips is None:
                    desc += "（直连探测无应答，无法确认是否被劫持）"
        result.append((s, kind, desc))
    bad = any(kind not in ("proxy", "hijack") for _, kind, _ in result)
    return bad, result


def _is_fake(ip):
    try:
        return ipaddress.ip_address(ip) in FAKE_IP_NET
    except ValueError:
        return False


def http_get(opener, url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "dns-leak-test/1.0"})
    with opener.open(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def rand_label(n=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def trigger(opener, host, mode):
    """触发对 host 的 DNS 查询；返回值无所谓，查询本身才是目的"""
    if mode in ("system", "both"):
        try:
            socket.getaddrinfo(host, 80)
        except Exception:
            pass
    if mode in ("proxy", "both"):
        try:
            http_get(opener, f"http://{host}/", timeout=6)
        except Exception:
            pass


def is_local(entry, local_country):
    country = (entry.get("country_name") or "").lower()
    asn = (entry.get("asn") or "").lower()
    if local_country and country == local_country.lower():
        return True
    return any(k in asn for k in CN_ASN_KEYWORDS)


def fmt(entry):
    return f"{entry.get('ip', '?'):<40} {entry.get('country_name', '?'):<16} {entry.get('asn', '?')}"


def main():
    ap = argparse.ArgumentParser(description="代理线路 DNS 泄漏检测")
    ap.add_argument("--proxy", help="HTTP 代理地址，如 http://127.0.0.1:7890；不填则用系统/环境变量代理")
    ap.add_argument("--mode", choices=["system", "proxy", "both"], default="both",
                    help="触发查询的方式（默认 both）")
    ap.add_argument("--count", type=int, default=10, help="随机子域名数量（默认 10）")
    ap.add_argument("--local-country", default="China",
                    help="你本地所在国家（英文，用于判断泄漏，默认 China）")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出原始结果")
    args = ap.parse_args()

    opener = build_opener(args.proxy)

    print(color("[1/3] 申请测试 ID ...", CYAN))
    try:
        test_id = http_get(opener, f"https://{API_HOST}/id").strip()
    except Exception as e:
        sys.exit(f"无法连接 {API_HOST}：{e}\n请确认代理已开启、端口正确。")
    if not test_id.isalnum() or len(test_id) > 64:
        sys.exit(f"返回的 ID 异常：{test_id!r}")

    print(color(f"[2/3] 触发 {args.count} 个随机域名查询（模式：{args.mode}）...", CYAN))
    hosts = [f"{rand_label()}.{test_id}.{API_HOST}" for _ in range(args.count)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(lambda h: trigger(opener, h, args.mode), hosts))

    print(color("[3/3] 获取检测结果 ...", CYAN))
    try:
        raw = http_get(opener, f"https://{API_HOST}/dnsleak/test/{test_id}?json", timeout=20)
        data = json.loads(raw)
    except Exception as e:
        sys.exit(f"获取结果失败：{e}")

    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return

    # 没有任何记录时 bash.ws 可能返回字典 / 字符串而不是列表
    if isinstance(data, dict):
        data = data.get("data") or data.get("result") or []
    if not isinstance(data, list):
        data = []
    data = [d for d in data if isinstance(d, dict)]

    exits = [d for d in data if d.get("type") == "ip"]
    dns = [d for d in data if d.get("type") == "dns"]

    print()
    print(color("出口 IP：", BOLD))
    for e in exits:
        print("  " + fmt(e))
    print(color(f"\n查询过测试域名的 DNS 服务器（{len(dns)} 个）：", BOLD))
    for d in dns:
        tag = color("  [本地/国内]", RED) if is_local(d, args.local_country) else ""
        print("  " + fmt(d) + tag)

    # ---------- 本机系统 DNS ----------
    sys_bad, sys_list = (None, [])
    if args.mode in ("system", "both"):
        sys_bad, sys_list = check_system_dns(e.get("ip") for e in exits)
        print(color("\n本机系统 DNS（操作系统当前使用的解析器）：", BOLD))
        if not sys_list:
            print("  （读取失败，跳过本项）")
        for ip, kind, desc in sys_list:
            c = GREEN if kind in ("proxy", "hijack") else (RED if kind in ("cn", "lan") else YELLOW)
            print(f"  {ip:<40} " + color(desc, c))

    # ---------- 结论 ----------
    print(color("\n结论：", BOLD))
    exit_local = [e for e in exits if is_local(e, args.local_country)]
    dns_local = [d for d in dns if is_local(d, args.local_country)]
    exit_asns = {e.get("asn") for e in exits}

    if exit_local:
        print(color("  ✗ 出口 IP 就在本地/国内 —— 流量根本没走代理，先检查代理是否生效。", RED))
    if sys_bad:
        print(color("  ✗ 系统 DNS 没有被代理接管：系统发出的域名查询会绕过代理、明文发出。", RED))
        print("    即使解析器在境外（如 1.1.1.1），运营商也能看到你查询了哪些域名。")
        print("    修复：开启 TUN / 虚拟网卡模式 + DNS 劫持（any:53），"
              "开启后重新运行，系统 DNS 应显示为绿色（代理地址或「被代理劫持」）。")
    if not dns:
        print(color("  ? 没有记录到任何 DNS 查询，结果不确定。", YELLOW))
        print("    可能原因：fake-ip 模式下系统查询被本地拦截、且代理请求超时；"
              "可尝试 --proxy 指定端口或 --mode proxy 重测。")
    elif dns_local:
        print(color(f"  ✗ 存在 DNS 泄漏：{len(dns_local)} 个 DNS 服务器位于本地/国内运营商。", RED))
        print("    常见原因：")
        print("    - 分流规则里 GEOIP / IP-CIDR 没加 no-resolve，匹配前先用国内 DNS 解析了域名")
        print("    - 非 TUN 模式下，浏览器/系统直接用运营商 DNS")
        print("    - Mihomo 的 nameserver 用了国内 DNS 且未配置 nameserver-policy / fallback")
        print("    - 浏览器开启了「安全 DNS（DoH）」直连国内 DoH")
    elif sys_bad:
        print("  · 检测站记录到的 DNS 都在境外，但这正是上面「系统 DNS 明文直连境外解析器」的结果，"
              "不代表安全。")
    else:
        same = [d for d in dns if d.get("asn") in exit_asns]
        print(color("  ✓ 未发现 DNS 泄漏：所有 DNS 查询都不在本地/国内。", GREEN))
        if len(same) < len(dns):
            print("    （部分 DNS 属于 Cloudflare / Google 等公共解析，"
                  "这是 VPS 上游 DNS 的正常表现，不算泄漏。）")

    conclusion = [d for d in data if d.get("type") == "conclusion" and d.get("ip")]
    if conclusion:
        verdict = conclusion[0]["ip"]
        print(color(f"\n  bash.ws 原始判定：{verdict}", CYAN))
        if "leak" in verdict.lower() and dns and not dns_local and not sys_bad:
            print("    注：bash.ws 只要发现 DNS 服务器和出口 IP 不属于同一运营商就会提示 may be leaking；"
                  "这里所有 DNS 都在境外公共解析，以上方结论为准。")


if __name__ == "__main__":
    main()
