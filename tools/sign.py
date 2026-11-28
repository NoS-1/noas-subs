#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sign.py —— 规则仓 manifest 的 ECDSA P-256 签名与验签。

密钥口径（对齐 App 端 SignedConfig）：
  · 算法：SHA256withECDSA，曲线 prime256v1 (P-256)；签名为原始 DER 字节；
  · 私钥仅存发布机，绝不入库、不入 APK；公钥随 App 内置验签；
  · 私钥路径：环境变量 NX_SUBS_SIGN_KEY，默认 ~/.nx/subs-sign-p256.pem；
  · 公钥 PEM 默认同目录 subs-sign-p256-pub.pem。

子命令：
  genkey            生成新密钥对（覆盖前先确认；旧公钥需同步替换 App 内置）
  sign <manifest>   对 manifest 文件字节签名，写出 <manifest>.sig（DER 原始字节）
  verify <manifest> <sig> [pub.pem]   验签，退出码 0 通过 / 1 失败
  pub               打印私钥对应公钥的 Base64（X.509 DER 体，供 App 内置）
"""
import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

KEY_DIR = os.environ.get("NX_SUBS_KEY_DIR", os.path.expanduser("~/.nx"))
PRIV_PATH = os.environ.get("NX_SUBS_SIGN_KEY", os.path.join(KEY_DIR, "subs-sign-p256.pem"))
PUB_PATH = os.path.join(KEY_DIR, "subs-sign-p256-pub.pem")


def _priv():
    if not os.path.exists(PRIV_PATH):
        raise SystemExit("私钥不存在：%s（先 genkey，或设置 NX_SUBS_SIGN_KEY）" % PRIV_PATH)
    with open(PRIV_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def _load_pub(pub_path=None):
    path = pub_path or PUB_PATH
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


def genkey():
    if os.path.exists(PRIV_PATH):
        raise SystemExit("私钥已存在：%s（如需轮换先备份/删除）" % PRIV_PATH)
    priv = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    os.makedirs(KEY_DIR, exist_ok=True)
    with open(PRIV_PATH, "wb") as f:
        f.write(priv_pem)
    os.chmod(PRIV_PATH, 0o600)
    with open(PUB_PATH, "wb") as f:
        f.write(pub_pem)
    print("私钥（仅发布机留存，600）：%s" % PRIV_PATH)
    print("公钥 PEM：%s" % PUB_PATH)
    print("App 内置公钥 Base64 体：")
    print(pub_base64(priv.public_key()))


def pub_base64(pub):
    import base64
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


def sign_file(manifest_path):
    priv = _priv()
    with open(manifest_path, "rb") as f:
        data = f.read()
    sig = priv.sign(data, ec.ECDSA(hashes.SHA256()))
    sig_path = manifest_path + ".sig"
    with open(sig_path, "wb") as f:
        f.write(sig)
    print("签名写出：%s（DER %d 字节）" % (sig_path, len(sig)))


def verify_file(manifest_path, sig_path, pub_path=None):
    with open(manifest_path, "rb") as f:
        data = f.read()
    with open(sig_path, "rb") as f:
        sig = f.read()
    # 兼容 Base64 文本签名（App 端 decodeSignature 也兼容两种形态）
    if sig and all(c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n"
                   for c in sig):
        import base64
        try:
            sig = base64.b64decode(sig)
        except Exception:
            pass
    pub = _load_pub(pub_path)
    try:
        pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        print("验签通过")
        return 0
    except Exception as e:
        print("验签失败：%s" % e)
        return 1


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    cmd = argv[1]
    if cmd == "genkey":
        genkey()
    elif cmd == "sign":
        sign_file(argv[2])
    elif cmd == "verify":
        pub = argv[4] if len(argv) > 4 else None
        return verify_file(argv[2], argv[3], pub)
    elif cmd == "pub":
        print(pub_base64(_priv().public_key()))
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
