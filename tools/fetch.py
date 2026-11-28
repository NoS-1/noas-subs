#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fetch.py —— 并发拉取上游规则源，落 cache/ 并记录元信息。

设计要点：
  1. 全部公开 raw / 直链，不带凭证；
  2. 单源失败不影响整体：记录原因，失败源沿用上一轮缓存；
  3. GitHub raw 按 raw -> gh-proxy.com -> ghfast.top 轮换兜底；非 raw 直链只走直连；
  4. 记录字节数/耗时/新鲜度，供上游存活判定。
"""
import concurrent.futures as cf
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(ROOT, "cache")
STATE = os.path.join(CACHE, "sources.json")
UA = "NX-subs-fetch/1.0 (+https://gitee.com/NX8/noas-subs)"

MIRRORS = ["https://gh-proxy.com/", "https://ghfast.top/"]


def load_sources():
    out = []
    with open(os.path.join(ROOT, "sources.tsv"), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            name, url, fmt, kind = parts[:4]
            note = parts[4] if len(parts) > 4 else ""
            out.append({"name": name, "url": url, "fmt": fmt, "kind": kind, "note": note})
    return out


def slug(name):
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name).lower()


def candidates(url):
    """返回拉取候选 URL 列表：原始直连优先，GitHub raw 追加镜像前缀兜底。"""
    out = [url]
    if url.startswith("https://raw.githubusercontent.com/"):
        for m in MIRRORS:
            out.append(m + url)
    return out


def _curl_get(url, timeout=90):
    exe = shutil.which("curl")
    if not exe:
        raise RuntimeError("curl 不可用")
    fd, path = tempfile.mkstemp(suffix=".bin")
    os.close(fd)
    try:
        r = subprocess.run(
            [exe, "-fsSL", "--retry", "2", "--retry-connrefused", "-m", str(int(timeout)),
             "-A", UA, "-H", "Accept-Encoding: identity", "-H", "Cache-Control: no-cache",
             "-o", path, url],
            capture_output=True, timeout=timeout + 20)
        size = os.path.getsize(path) if os.path.exists(path) else 0
        if r.returncode != 0 or size < 128:
            raise RuntimeError("curl rc=%s size=%d" % (r.returncode, size))
        with open(path, "rb") as f:
            return f.read()
    finally:
        if os.path.exists(path):
            os.unlink(path)


def _get(url, timeout=30):
    headers = {"User-Agent": UA, "Accept": "*/*"}
    req = urllib.request.Request(url, headers=headers)
    buf = bytearray()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            buf += chunk
    return bytes(buf)


def fetch_one(src, state):
    dst = os.path.join(CACHE, slug(src["name"]) + ".txt")
    meta = state.get(src["name"]) or {}
    t0 = time.time()
    last_why = ""
    for url in candidates(src["url"]):
        try:
            body = _get(url)
            if len(body) < 128:
                raise RuntimeError("响应太小（疑似错误页）")
            with open(dst, "wb") as f:
                f.write(body)
            return {**src, "ok": True, "bytes": len(body), "sec": round(time.time() - t0, 2),
                    "via": url, "updated": int(time.time())}
        except urllib.error.HTTPError as e:
            last_why = "HTTP %d" % e.code
        except Exception as e:
            last_why = str(e)[:80]
            try:
                body = _curl_get(url)
                with open(dst, "wb") as f:
                    f.write(body)
                return {**src, "ok": True, "bytes": len(body), "sec": round(time.time() - t0, 2),
                        "via": url, "updated": int(time.time())}
            except Exception:
                pass
    # 全失败：沿用上轮缓存，标 stale
    if os.path.exists(dst):
        return {**src, "ok": True, "bytes": os.path.getsize(dst),
                "sec": round(time.time() - t0, 2), "cached": True, "stale": True,
                "why": last_why, "updated": meta.get("updated", 0)}
    return {**src, "ok": False, "why": last_why or "拉取失败", "sec": round(time.time() - t0, 2)}


def main():
    os.makedirs(CACHE, exist_ok=True)
    state = {}
    if os.path.exists(STATE):
        try:
            state = json.load(open(STATE, encoding="utf-8"))
        except Exception:
            state = {}
    sources = load_sources()
    results = []
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(fetch_one, s, state): s for s in sources}
        for fu in cf.as_completed(futs):
            results.append(fu.result())

    fresh, cached, failed = [], [], []
    for r in results:
        if not r.get("ok"):
            failed.append(r)
        elif r.get("cached"):
            cached.append(r)
        else:
            fresh.append(r)
    for r in results:
        if r.get("ok"):
            state[r["name"]] = {k: r.get(k, "") for k in ("bytes", "updated", "via")}
    json.dump(state, open(STATE, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    print("规则源：成功 %d（新拉 %d／缓存 %d）｜失败 %d／共 %d" % (
        len(fresh) + len(cached), len(fresh), len(cached), len(failed), len(results)))
    for r in failed:
        print("  ✗ %-18s %s" % (r["name"], r.get("why", "")))
    for r in results:
        if r.get("ok") and r.get("stale"):
            print("  ⚠ %-18s 沿用缓存：%s" % (r["name"], r.get("why", "")))
    if len(failed) >= len(results) and results:
        print("FAIL：所有源都拉不到（网络受限或上游集体故障）")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
