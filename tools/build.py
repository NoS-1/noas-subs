#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build.py —— 规则仓总编排：出两套形态。

方案一 · 独立订阅链接：standalone/<full|mid|lite>/ 多格式，外部客户端直填。
方案二 · App 互联：仓根 domains.txt / whitelist.txt / subs-manifest.json / .sig，
        对接壳侧 SubscriptionSync 双通道拉取、验签、版本闸。

用法：
  python3 tools/build.py              # 先拉取上游再构建
  python3 tools/build.py --offline    # 跳过网络，只吃 cache/ 现有缓存（离线验收用）
  python3 tools/build.py --no-sign    # 不写签名（联调/验签未接前用）
"""
import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import compile as C  # noqa: E402
import fetch as F    # noqa: E402

STANDALONE = os.path.join(ROOT, "standalone")
CHANNEL_FILES = ("domains.txt", "whitelist.txt", "subs-manifest.json")


def file_stat(path):
    data = open(path, "rb").read()
    lines = [ln for ln in data.decode("utf-8", errors="ignore").splitlines() if ln.strip()]
    return {"sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data), "nonempty_lines": len(lines)}


def drop_children(exact):
    """父域已覆盖时删子域（压缩体积，后缀匹配语义不变）。"""
    keep = []
    for d in exact:
        parts = d.split(".")
        covered = any(".".join(parts[i:]) in exact for i in range(1, len(parts) - 1))
        if not covered:
            keep.append(d)
    return set(keep)


def tier_domains(exact, hitn, tier):
    if tier == "full":
        return set(exact)
    multi = {d for d in exact if hitn.get(d, 1) >= 2}
    if tier == "mid":
        return multi if len(multi) >= 500 else set(exact)
    if tier == "lite":
        lite = drop_children(multi) if multi else set(exact)
        return lite if len(lite) >= 200 else set(exact)
    return set(exact)


def write_standalone_tiers(exact, wild, hitn):
    out = {}
    for tier in ("full", "mid", "lite"):
        doms = tier_domains(exact, hitn, tier)
        meta = C.write_standalone(doms, wild, os.path.join(STANDALONE, tier), kind=tier)
        out[tier] = meta
        print("  standalone/%-4s 拦截 %5d 通配 %2d" % (tier, meta["count"], meta["wildcards"]))
    return out


def _write_gz(src):
    import gzip
    with open(src, "rb") as f:
        data = f.read()
    with gzip.open(src + ".gz", "wb", compresslevel=9) as f:
        f.write(data)


def ensure_emergency():
    """云端急救配置兜底：缺省时写空名单模板，端侧验签后按空名单保守运行。"""
    d = os.path.join(ROOT, "cloud")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "emergency.json")
    if not os.path.exists(p):
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"version": 0, "allow": [], "block": [], "bypass": [], "model": {}},
                      f, ensure_ascii=False, indent=1)
            f.write("\n")
    return p


def write_channels(exact, wl):
    os.makedirs(ROOT, exist_ok=True)
    black = sorted(exact)
    white = sorted(wl)
    domains_p = os.path.join(ROOT, "domains.txt")
    white_p = os.path.join(ROOT, "whitelist.txt")
    with open(domains_p, "w", encoding="utf-8") as f:
        f.write("\n".join(black) + ("\n" if black else ""))
    with open(white_p, "w", encoding="utf-8") as f:
        f.write("\n".join(white) + ("\n" if white else ""))
    # Gitee 通道优先拉 .gz 副本，失败再回退 Contents API 明文；顺手提供压缩副本
    _write_gz(domains_p)
    _write_gz(white_p)

    version = int(time.strftime("%Y%m%d%H%M", time.gmtime()))
    manifest = {
        "version": version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": {
            "domains.txt": file_stat(domains_p),
            "whitelist.txt": file_stat(white_p),
        },
    }
    manifest_p = os.path.join(ROOT, "subs-manifest.json")
    with open(manifest_p, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1)
        f.write("\n")
    return manifest_p, manifest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="跳过网络拉取，只吃缓存")
    ap.add_argument("--no-sign", action="store_true", help="不写 manifest 签名")
    args = ap.parse_args()

    sources = F.load_sources()
    print("台账源 %d 条（拦截 %d／白名单 %d）" % (
        len(sources), sum(s["kind"] == "block" for s in sources),
        sum(s["kind"] == "allow" for s in sources)))

    if not args.offline:
        rc = F.main()
        if rc not in (0,):
            print("WARN：拉取阶段返回 %d，继续沿缓存构建" % rc)

    exact, wild, per_source, hitn = C.collect(sources)
    wl = C.collect_allow(sources)
    exact, dropped = C.apply_whitelist(exact, wl)

    print("聚合：拦截候选 %d 通配 %d｜白名单 %d｜白名单闸剔除 %d" % (
        len(exact), len(wild), len(wl), len(dropped)))
    for name, n in per_source.items():
        print("  · %-18s %d 条" % (name, n))

    write_standalone_tiers(exact, wild, hitn)
    manifest_p, manifest = write_channels(exact, wl)
    emergency_p = ensure_emergency()
    print("App 通道：domains.txt %d 条｜whitelist.txt %d 条｜version %d" % (
        manifest["files"]["domains.txt"]["nonempty_lines"],
        manifest["files"]["whitelist.txt"]["nonempty_lines"],
        manifest["version"]))

    if not args.no_sign:
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import sign
        sign.sign_file(manifest_p)
        sign.sign_file(emergency_p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
