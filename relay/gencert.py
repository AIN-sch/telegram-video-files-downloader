# 生成自签 ECDSA P-256 证书，用于 TLS1.3，CN 与客户端 SNI 保持一致

import argparse
import datetime
import hashlib
import os
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

BASE = os.path.dirname(os.path.abspath(__file__))
KEYS = os.path.join(BASE, "keys")
CN = "www.microsoft.com"


def main():
    ap = argparse.ArgumentParser(description="生成自签证书")
    ap.add_argument("--out", default=KEYS, help="证书输出目录")
    ap.add_argument("--cn", default=CN, help="证书 CN，与客户端 SNI 一致")
    cfg = ap.parse_args()

    keys = os.path.abspath(cfg.out)
    os.makedirs(keys, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cfg.cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cfg.cn)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    kp = os.path.join(keys, "key.pem")
    cp = os.path.join(keys, "cert.pem")
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(kp, 0o600)
    except Exception:
        pass
    der = cert.public_bytes(serialization.Encoding.DER)
    print("key  :", kp)
    print("cert :", cp)
    print("pin  :", hashlib.sha256(der).hexdigest())


if __name__ == "__main__":
    main()
