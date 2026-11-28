# nx-subs —— NX 独立规则仓

公开上游规则源的聚合发布仓，同一套台账出两套形态：

- **方案一 · 独立订阅链接**：`standalone/<full|mid|lite>/` 多格式，AdGuard Home / Pi-hole / sing-box / Clash 等外部客户端直接填，不依赖 App。
- **方案二 · App 互联**：仓根 `domains.txt` / `whitelist.txt` / `subs-manifest.json` / `subs-manifest.json.sig`，对接壳侧 `SubscriptionSync` 双通道拉取、ECDSA 验签、版本单调闸、摘要校验。

规则与源台账不内置进 APK；端侧与外部客户端只连本仓，不直连第三方上游。

## 目录

```
nx-subs/
├── sources.tsv            # 上游台账：名称·URL·格式·类型(block/allow)·说明
├── cache/                 # 上游拉取缓存（不入库）
├── channels/              # 预留：App 通道说明（产物落仓根，对齐壳侧常量）
├── standalone/
│   ├── full/  mid/  lite/ # 三档多格式订阅
│   └── ...                # adguard/domains/hosts/dnsmasq/clash/singbox/qx/rpz/wildcards/meta
├── domains.txt            # 【App 通道】拦截域
├── whitelist.txt          # 【App 通道】放行域
├── domains.txt.gz / whitelist.txt.gz   # Gitee 通道压缩副本
├── subs-manifest.json      # 【App 通道】version / files 摘要
├── subs-manifest.json.sig  # 【App 通道】ECDSA P-256 DER 签名
├── tools/
│   ├── fetch.py           # 并发拉取 + 镜像轮换兜底 + 缓存沿用
│   ├── compile.py          # 解析/归一化/白名单父域保护/多格式产出
│   ├── build.py            # 总编排：standalone 三档 + App 通道产物 + 签名
│   └── sign.py             # P-256 密钥生成 / 签名 / 验签
└── tests/test_pipeline.py # 纯逻辑离线单测
```

## 上游台账口径

- 来源：《国内加速版订阅清单》筛选；旧源全部废弃，只认本台账。当前 11 条（拦截 10／白名单 1）。
- 已纳入：anti-ad easylist、AWAvenue 猫队、ad-wars 大圣、cjxlist、cjx-annoyance、yhosts、liwenjie119、Zisbusy、rssvcn、halflife-ad；白名单 dangchu。
- 已剔除：
  - 大合集：halflife `ad-pc.txt`（PC 网页向、11 万域）、HaGeZi `multi.txt`（海外跟踪/钓鱼/挖矿，18 万域）；
  - 同源重复：privacy-protection-tools `anti-ad-easylist.txt`（与 anti-ad.net 同源）；
  - 误标白名单：`anti-ad.net/domains.txt`（实测为拦截域清单）；
  - 非独立源：gh-proxy / ghfast / ghproxy 镜像前缀兜底行。
- 链路口径：台账存 GitHub raw 原始 URL；`fetch` 按 `raw.githubusercontent.com → gh-proxy.com → ghfast.top` 轮换兜底；anti-ad.net 直链无镜像。
- 格式：`hosts` / `adblock` / `domains` / `adblock-allow`（`@@||域^$` 例外）/ `wildcard`。

## 构建

```bash
# 拉取上游并构建（含签名）
python3 tools/build.py

# 离线验收：只吃 cache/ 现有缓存，不发网络
python3 tools/build.py --offline

# 不写签名（验签通道未接前联调用）
python3 tools/build.py --no-sign

# 单测
python3 -m unittest -v tests.test_pipeline
```

分档口径：`full` = 全部并集；`mid` = 多源共识（命中 ≥2 源）；`lite` = 共识集去父域覆盖压缩。阈值见 `build.py: tier_domains`。

## App 通道契约（对齐 SubscriptionSync）

- 拉取双通道：Gitee 主 `https://gitee.com/NX8/nx-subs/raw/main/`，GitHub 备 `https://raw.githubusercontent.com/NX920/nx-subs/main/`。
- manifest：`{"version": <i64>, "generated_at": <ISO>, "files": {<name>: {"sha256", "size", "nonempty_lines"}}}`。
- 签名：ECDSA `SHA256withECDSA`，曲线 P-256（prime256v1），签名为原始 DER 字节；App 端 `SignedConfig` 内置公钥验签。
- Gitee 大名单先拉 `.gz` 副本，失败回退 Contents API 明文。

## 密钥口径

- 私钥仅存发布机，**不入库、不入包**：`~/.nx/subs-sign-p256.pem`（600）；公钥 `~/.nx/subs-sign-p256-pub.pem`。
- 生成：`python3 tools/sign.py genkey`；签名：`sign.py sign <manifest>`；验签：`sign.py verify <manifest> <sig>`。
- **待接**：新 P-256 公钥 Base64 体需替换 App `SignedConfig.kt` 内置公钥后重出包；当前壳侧内置的仍是旧公钥（旧私钥已丢失）。

## 待办

- [ ] 远端推送：本地规则仓推送到 Gitee `NX8/nx-subs`（主）+ GitHub `NX920/nx-subs`（备），分支 `main`。
- [ ] App 内置公钥轮换为本仓新公钥，重出包。
- [ ] 远端推送前复核：manifest 摘要与 `domains.txt` / `whitelist.txt` 一致。
