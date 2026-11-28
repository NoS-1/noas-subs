#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""规则仓纯逻辑离线单测：解析 / 归一化 / 白名单闸 / 多格式 / 签名验签闭环。

运行：python3 -m unittest -v tests.test_pipeline
"""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import compile as C  # noqa: E402
import sign          # noqa: E402


def write_cache(cache_dir, name, text):
    os.makedirs(cache_dir, exist_ok=True)
    with open(os.path.join(cache_dir, C.slug(name) + ".txt"), "w", encoding="utf-8") as f:
        f.write(text)


class TestParsers(unittest.TestCase):
    def test_hosts(self):
        text = "0.0.0.0 ads.example.com\n127.0.0.1 track.example.org\n# 注释\n1.2.3.4 bad.com\n"
        got = set(C.parse_hosts(text))
        self.assertEqual(got, {"ads.example.com", "track.example.org"})

    def test_adblock(self):
        text = "||tracker.com^\n||x.com^$third-party\n! 注释\n||*.wild.com^\n"
        got = set(C.parse_adblock(text))
        self.assertEqual(got, {"tracker.com", "x.com", "W:wild.com"})
        wild = set(C.parse_wildcard(text))
        self.assertEqual(wild, {"W:wild.com"})

    def test_adblock_partial_wildcard_skipped(self):
        # 部分标签通配（p*.host）纯域名清单无法表达，应跳过
        text = "||p*.bdxiguaimg.com^$important\n||ok.example.com^\n"
        got = set(C.parse_adblock(text))
        self.assertEqual(got, {"ok.example.com"})

    def test_adblock_allow(self):
        text = "@@||appcfg.v.qq.com^\n@@||m-api.uc.cn^$important\n! 注释\n# c\n"
        got = set(C.parse_adblock_allow(text))
        self.assertEqual(got, {"appcfg.v.qq.com", "m-api.uc.cn"})

    def test_adblock_allow_wildcard(self):
        text = "@@||*.anjuke.com^\n@@||*.a.yximgs.com^$important\n"
        got = set(C.parse_adblock_allow(text))
        self.assertEqual(got, {"anjuke.com", "a.yximgs.com"})
        # 白名单通配裸域按父域保护任意子域
        keep, dropped = C.apply_whitelist({"m.anjuke.com", "ok.net"}, got)
        self.assertEqual(keep, {"ok.net"})
        self.assertEqual(dropped, ["m.anjuke.com"])

    def test_domains(self):
        text = "ad.one.com\nDOMAIN-SUFFIX,ad.two.com\n# c\naddress=/ad.three.com/#\n"
        got = set(C.parse_domains(text))
        self.assertEqual(got, {"ad.one.com", "ad.two.com", "ad.three.com"})


class TestNorm(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(C.norm("AD.Example.COM"), "ad.example.com")
        self.assertEqual(C.norm("||a.com^"), "a.com")
        self.assertEqual(C.norm("http://b.com/path"), "b.com")

    def test_drop(self):
        self.assertEqual(C.norm("192.168.1.1"), "")
        self.assertEqual(C.norm("10.0.0.5"), "")
        self.assertEqual(C.norm("localhost"), "")
        self.assertEqual(C.norm("singlelabel"), "")
        self.assertEqual(C.norm("172.16.0.1"), "")
        self.assertEqual(C.norm("113.105.248.169"), "")
        self.assertEqual(C.norm(""), "")


class TestWhitelistGate(unittest.TestCase):
    def test_parent_protection(self):
        wl = {"example.com"}
        keep, dropped = C.apply_whitelist({"x.example.com", "other.com"}, wl)
        self.assertEqual(keep, {"other.com"})
        self.assertEqual(dropped, ["x.example.com"])

    def test_exact_match(self):
        wl = {"other.com"}
        keep, dropped = C.apply_whitelist({"other.com", "a.net"}, wl)
        self.assertEqual(keep, {"a.net"})
        self.assertEqual(dropped, ["other.com"])


class TestCollectAndFormat(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cache = os.path.join(self.tmp, "cache")
        write_cache(self.cache, "h1",
                    "0.0.0.0 alpha.com\n0.0.0.0 beta.com\n127.0.0.1 gamma.com\n")
        write_cache(self.cache, "a1", "||alpha.com^\n||delta.io^\n")
        write_cache(self.cache, "w1", "allow.good.com\n")
        self.sources = [
            {"name": "h1", "url": "u", "fmt": "hosts", "kind": "block"},
            {"name": "a1", "url": "u", "fmt": "adblock", "kind": "block"},
            {"name": "w1", "url": "u", "fmt": "domains", "kind": "allow"},
        ]

    def test_collect_dedup_and_allow(self):
        exact, wild, per_source, hitn = C.collect(self.sources, self.cache)
        # alpha.com 两源命中，beta/gamma 仅 hosts，delta.io 仅 adblock
        self.assertIn("alpha.com", exact)
        self.assertIn("beta.com", exact)
        self.assertIn("gamma.com", exact)
        self.assertIn("delta.io", exact)
        self.assertEqual(hitn["alpha.com"], 2)
        wl = C.collect_allow(self.sources, self.cache)
        self.assertEqual(wl, {"allow.good.com"})

    def test_whitelist_gate_drops_children(self):
        exact, _, _, _ = C.collect(self.sources, self.cache)
        wl = {"alpha.com"}
        keep, dropped = C.apply_whitelist(exact, wl)
        self.assertNotIn("alpha.com", keep)
        self.assertIn("beta.com", keep)

    def test_write_formats(self):
        exact, wild, _, _ = C.collect(self.sources, self.cache)
        wl = C.collect_allow(self.sources, self.cache)
        exact, _ = C.apply_whitelist(exact, wl)
        out = os.path.join(self.tmp, "standalone", "full")
        meta = C.write_standalone(exact, wild, out, kind="full")
        doms = open(os.path.join(out, "domains.txt"), encoding="utf-8").read().split()
        self.assertEqual(doms, sorted(doms))  # 排序
        adg = open(os.path.join(out, "adguard.txt"), encoding="utf-8").read()
        for d in doms:
            self.assertIn("||%s^" % d, adg)
        hosts = open(os.path.join(out, "hosts.txt"), encoding="utf-8").read()
        for d in doms:
            self.assertIn("0.0.0.0 %s" % d, hosts)
        self.assertEqual(meta["count"], len(doms))
        self.assertTrue(os.path.exists(os.path.join(out, "meta.json")))


class TestSigning(unittest.TestCase):
    def test_sign_verify_roundtrip(self):
        tmp = tempfile.mkdtemp()
        sign.PRIV_PATH = os.path.join(tmp, "priv.pem")
        sign.PUB_PATH = os.path.join(tmp, "pub.pem")
        sign.genkey()

        manifest = os.path.join(tmp, "subs-manifest.json")
        payload = {"version": 2026112801, "files": {"domains.txt": {"sha256": "x"}}}
        with open(manifest, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        sign.sign_file(manifest)
        sig = manifest + ".sig"
        self.assertTrue(os.path.exists(sig))
        self.assertEqual(sign.verify_file(manifest, sig), 0)

        # 篡改后验签必须失败
        with open(manifest, "w", encoding="utf-8") as f:
            json.dump({"version": 2026112899, "files": {}}, f)
        self.assertEqual(sign.verify_file(manifest, sig), 1)


if __name__ == "__main__":
    unittest.main()
