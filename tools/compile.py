#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""compile.py —— 把各上游源归一成可发布的拦截/放行规则。

流水线：
  1. 解析（hosts / adblock / 纯域名 / wildcard）→ 只留纯域名与通配后缀
  2. 归一：小写、去端口/路径、丢 IP、丢内网、丢单标签域、IDNA 转码
  3. 白名单硬闸：命中白名单（含父域/子域关系）的拦截域一律剔除
  4. 多格式产出：adguard / domains / hosts / dnsmasq / clash / singbox / qx / rpz / allow

本模块只做纯逻辑，不直接发网络；输入来自 fetch 落盘的 cache/ 缓存。
"""
import hashlib
import os
import re
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(ROOT, "cache")

DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$")
PRIVATE_SUFFIX = ("localhost",)


def parse_hosts(text):
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("!"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        if parts[0] not in ("0.0.0.0", "127.0.0.1", "::"):
            continue
        yield parts[1]


def parse_adblock(text):
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("[") or line.startswith("#"):
            continue
        # 通配二级：||*.host^（含选项）→ 归通配集合，裸域表示任意多级子域
        mw = re.match(r"^\|\|\*\.([^\^/$|*]+)\^?(?:\$[a-z0-9,-]+)?$", line)
        if mw:
            yield "W:" + mw.group(1)
            continue
        m = re.match(r"^\|\|([^\^/$|]+)\^?$", line)
        if not m:
            m = re.match(r"^\|\|([^\^/$|]+)\^?\$[a-z0-9,-]+$", line)
        if m:
            host = m.group(1)
            if "*" in host:  # 部分标签通配（如 p*.host）纯域名清单无法表达，跳过
                continue
            yield host


def parse_domains(text):
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("!"):
            continue
        if re.match(r"^(address=|server=)", line):
            m = re.match(r"^address=/([^/]+)/", line)
            if m:
                yield m.group(1)
            continue
        m = re.match(r"^(?:- +)?(?:DOMAIN-SUFFIX|DOMAIN),(\S+)$", line)
        if m:
            yield m.group(1)
            continue
        yield line.split()[0]


def parse_adblock_allow(text):
    """解析 @@||host^$important 这类白名单例外规则，提取放行域。"""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        # 白名单通配：@@||*.host^ → 裸域进白名单，按父域保护任意子域
        mw = re.match(r"^@@\|\|\*\.([^\^/$|*]+)\^?(?:\$[a-z0-9,-]+)?$", line)
        if mw:
            yield mw.group(1)
            continue
        m = re.match(r"^@@\|\|([^\^/$|]+)\^?(?:\$[a-z0-9,-]+)?$", line)
        if m and "*" not in m.group(1):
            yield m.group(1)


def parse_wildcard(text):
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^\|\|\*\.([^\^/$|]+)\^", line)
        if m:
            yield "W:" + m.group(1)
            continue
        m = re.match(r"^\*\.([a-z0-9][a-z0-9._-]*)$", line, re.I)
        if m:
            yield "W:" + m.group(1)


PARSERS = {"hosts": parse_hosts, "adblock": parse_adblock, "domains": parse_domains,
           "adblock-allow": parse_adblock_allow,
           "dnsmasq": parse_domains, "wildcard": parse_wildcard,
           "domainswild": parse_wildcard, "clash": parse_domains}


def norm(d):
    d = d.strip().lower().strip(".")
    d = re.sub(r"^[a-z]+://", "", d)
    if any(ord(c) > 127 for c in d):
        try:
            d = d.encode("idna").decode("ascii")
        except Exception:
            return ""
    if d.startswith("||"):
        d = d[2:]
    d = d.rstrip("^")
    if d.startswith("*"):
        d = d.lstrip("*").lstrip(".")
    d = d.split("/")[0].split(":")[0]
    if not d or d.count(".") < 1:
        return ""
    if d.startswith("10.") or d.startswith("192.168.") or d.startswith("172."):
        return ""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", d):  # IPv4 字面量不进域名清单
        return ""
    if any(d == s or d.endswith("." + s) for s in PRIVATE_SUFFIX):
        return ""
    if not DOMAIN_RE.match(d):
        return ""
    if len(d) > 253:
        return ""
    return d


def registrable(d):
    parts = d.split(".")
    if len(parts) < 2:
        return d
    cc2 = {"com.cn", "net.cn", "org.cn", "gov.cn", "co.uk", "com.au", "co.jp", "co.kr",
           "com.br", "com.mx", "com.tr", "com.tw", "com.hk", "com.sg", "com.my"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in cc2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def protected(d, wl):
    """白名单不仅保护精确域，也保护父域：wl 有 baidu.com 时，x.baidu.com 不能被拦。"""
    parts = d.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in wl:
            return True
    return False


def slug(name):
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name).lower()


def parse_source(src, cache_dir=CACHE):
    """读一个源缓存文件，返回 (exact 域集合, wild 通配集合, 解析条数)。"""
    fp = os.path.join(cache_dir, slug(src["name"]) + ".txt")
    exact, wild, n = set(), set(), 0
    if not os.path.exists(fp):
        return exact, wild, n
    parser = PARSERS.get(src["fmt"], parse_domains)
    try:
        text = open(fp, encoding="utf-8", errors="ignore").read()
    except Exception:
        return exact, wild, n
    seen = set()
    for raw in parser(text):
        if raw.startswith("W:"):
            w = norm(raw[2:])
            if w:
                wild.add(w)
            continue
        d = norm(raw)
        if d:
            exact.add(d)
            seen.add(d)
            n += 1
    return exact, wild, n


def collect(sources, cache_dir=CACHE):
    """聚合所有源。返回：
      exact: 拦截精确域集合；wild: 通配集合；
      per_source: 源名 -> 解析条数；hitn: 域 -> 命中独立源个数。
    """
    exact, wild, per_source, hitn = set(), set(), {}, {}
    for s in sources:
        if s["kind"] == "allow":
            continue
        e, w, n = parse_source(s, cache_dir)
        exact |= e
        wild |= w
        per_source[s["name"]] = n
        for d in e:
            hitn[d] = hitn.get(d, 0) + 1
    return exact, wild, per_source, hitn


def collect_allow(sources, cache_dir=CACHE):
    """聚合白名单源，返回放行域集合。"""
    wl = set()
    for s in sources:
        if s["kind"] != "allow":
            continue
        e, _, _ = parse_source(s, cache_dir)
        wl |= e
    return wl


def apply_whitelist(domains, wl):
    """白名单硬闸：命中白名单（含父域）的拦截域剔除。返回 (保留集, 剔除集)。"""
    keep, dropped = set(), []
    for d in domains:
        if protected(d, wl):
            dropped.append(d)
        else:
            keep.add(d)
    return keep, dropped


def _sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def write_standalone(domains, wild, outdir, kind, title="NX 拦截订阅", home="https://gitee.com/NX8/nx-subs"):
    """产出独立订阅多格式到 outdir。返回 meta dict。"""
    os.makedirs(outdir, exist_ok=True)
    doms = sorted(domains)
    wilds = sorted(w for w in wild if w not in set(doms))
    ts = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    body_hash = hashlib.sha256(("\n".join(doms) + "|" + "\n".join(wilds)).encode()).hexdigest()[:8]
    ver = time.strftime("%Y%m%d") + "-" + body_hash

    files = {}
    head = ["! Title: %s（%s）" % (title, kind),
            "! Description: 公开上游源并集，白名单硬闸过滤后发布",
            "! Version: %s" % ver,
            "! Last modified: %s" % ts,
            "! Expires: 12 hours",
            "! Homepage: %s" % home,
            "! 条数: %d（含通配 %d）" % (len(doms), len(wilds))]
    files["adguard.txt"] = "\n".join(head + [""] +
                                     ["||%s^" % d for d in doms] +
                                     ["||*.%s^" % w for w in wilds]) + "\n"
    files["domains.txt"] = "\n".join(doms) + "\n"
    files["hosts.txt"] = "\n".join(["# %s %s（%d 条）" % (title, ver, len(doms))] +
                                    ["0.0.0.0 %s" % d for d in doms]) + "\n"
    files["dnsmasq.conf"] = "\n".join(["# %s %s（%d 条）" % (title, ver, len(doms))] +
                                      ["address=/%s/#" % d for d in doms]) + "\n"
    files["clash.yaml"] = "\n".join(["# %s %s rule-provider payload" % (title, ver), "payload:"] +
                                    ["  - DOMAIN-SUFFIX,%s" % d for d in doms]) + "\n"
    files["singbox.json"] = __import__("json").dumps(
        {"version": 1, "rules": [{"domain_suffix": doms}]}, ensure_ascii=False, indent=1) + "\n"
    files["qx.list"] = "\n".join(["# %s %s（%d 条 + 通配 %d）" % (title, ver, len(doms), len(wilds))] +
                                 ["host-suffix, %s, reject" % d for d in doms] +
                                 ["host-suffix, %s, reject" % w for w in wilds]) + "\n"
    files["rpz.zone"] = "\n".join(["# %s RPZ（%s）" % (title, ver), "; $TTL 300"] +
                                  ["%s CNAME ." % d for d in doms] +
                                  ["*.%s CNAME ." % w for w in wilds]) + "\n"
    files["wildcards.txt"] = "\n".join(["# %s 通配（%s）：*.域 = 任意多级子域" % (title, ver)] +
                                       ["*.%s" % w for w in wilds]) + "\n"

    for name, text in files.items():
        with open(os.path.join(outdir, name), "w", encoding="utf-8") as f:
            f.write(text)

    meta = {"kind": kind, "version": ver, "count": len(doms), "wildcards": len(wilds),
            "generated_utc": ts, "files": {}}
    for name in sorted(files):
        p = os.path.join(outdir, name)
        meta["files"][name] = {"bytes": os.path.getsize(p),
                               "sha256": _sha256_bytes(open(p, "rb").read())}
    with open(os.path.join(outdir, "meta.json"), "w", encoding="utf-8") as f:
        __import__("json").dump(meta, f, ensure_ascii=False, indent=1)
    return meta
