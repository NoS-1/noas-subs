#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""aggregate_reports.py —— 端侧上报候选 / 误拦申诉的仓侧聚合骨架（纯本地，不联网）。

端侧上行两类事件（见壳侧 LogUploader.submitCandidates）：
  · candidate  {"type":"candidate","host":...,"count":N,"signals":...,"pkg":...,"pn":...}
  · misblock   {"type":"misblock","host":...,"pkg":...,"pn":...,"bucket":...,"reason":...}

本脚本把导出的 JSONL 日志按域名聚合频次、信号与申诉标记，产出待人工/规则复核队列，
供后续入仓裁决。当前为骨架：只做归并与排序，不自动把域名写入拦截/放行名单；
真正入仓仍需复核 + 签名发布（走 build.py 链路）。

用法：
  python3 tools/aggregate_reports.py <reports.jsonl> [-o review-queue.json]
  不带输入文件时打印用法并退出 0（骨架占位，不报错）。
"""
import argparse
import json
import os
import sys
from collections import OrderedDict


def aggregate(rows):
    """纯聚合：输入 dict 行列表，返回按候选频次倒序的待复核条目列表。"""
    queue = OrderedDict()
    for row in rows:
        if not isinstance(row, dict):
            continue
        etype = row.get("type")
        host = (row.get("host") or "").strip().lower().rstrip(".")
        if not host or etype not in ("candidate", "misblock"):
            continue
        item = queue.setdefault(host, {
            "host": host,
            "candidate_count": 0,
            "misblock": False,
            "signals": set(),
            "pkgs": set(),
            "labels": set(),
            "buckets": set(),
        })
        if etype == "candidate":
            try:
                item["candidate_count"] += int(row.get("count") or 1)
            except (TypeError, ValueError):
                item["candidate_count"] += 1
            for sig in str(row.get("signals") or "").split(","):
                if sig:
                    item["signals"].add(sig)
        else:
            item["misblock"] = True
            if row.get("bucket"):
                item["buckets"].add(str(row["bucket"]))
        if row.get("pkg"):
            item["pkgs"].add(str(row["pkg"]))
        if row.get("pn"):
            item["labels"].add(str(row["pn"]))

    out = []
    for item in queue.values():
        item["signals"] = sorted(item["signals"])
        item["pkgs"] = sorted(item["pkgs"])
        item["labels"] = sorted(item["labels"])
        item["buckets"] = sorted(item["buckets"])
        out.append(item)
    out.sort(key=lambda x: (x["misblock"], x["candidate_count"]), reverse=True)
    return out


def load_jsonl(path):
    rows = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


# 复核裁决合法取值：block 入拦截名单、allow 入放行名单、drop 不采纳。
VALID_VERDICTS = ("block", "allow", "drop")


def _norm(host):
    return (host or "").strip().lower().rstrip(".")


def resolve_decisions(queue, decisions):
    """按复核裁决把队列域名分桶为拦截 / 放行清单（纯函数，不写文件、不签名）。

    - queue: aggregate() 输出的待复核条目列表；
    - decisions: {host: "block" | "allow" | "drop"}，仅对队列内域名生效；
    - 未知域名、非法裁决一律忽略；misblock 申诉不会自动进入放行，必须显式 allow。

    返回 {"block": [sorted], "allow": [sorted]}。
    """
    known = {_norm(item.get("host")) for item in queue if isinstance(item, dict)}
    verdict_by_host = {}
    for raw_host, verdict in (decisions or {}).items():
        host = _norm(raw_host)
        if not host or host not in known or verdict not in VALID_VERDICTS:
            continue
        verdict_by_host[host] = verdict  # 同一域名后写裁决覆盖前写
    block = {h for h, v in verdict_by_host.items() if v == "block"}
    allow = {h for h, v in verdict_by_host.items() if v == "allow"}
    return {"block": sorted(block), "allow": sorted(allow)}


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("reports", nargs="?", help="导出的上报 JSONL 文件")
    ap.add_argument("-o", "--output", default="review-queue.json", help="待复核队列输出路径")
    args = ap.parse_args(argv)

    if not args.reports:
        print("骨架占位：提供上报 JSONL 路径后聚合 candidate/misblock 待复核域名。")
        return 0

    rows = load_jsonl(args.reports)
    queue = aggregate(rows)
    payload = {"version": 0, "review_count": len(queue), "items": queue}
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print("聚合待复核 %d 条 → %s" % (len(queue), os.path.abspath(args.output)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
