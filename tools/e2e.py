#!/usr/bin/env python3
"""Two real clients with real crypto against a running server. Needs: pip install cryptography.

Usage: e2e.py https://host:8443 [--load N]
       e2e.py --vectors out.json   (writes the vectors that client test suites verify)
"""
import base64, hashlib, json, os, ssl, sys, time, unicodedata, urllib.error, urllib.request, uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITER = 600_000
RAW = dict(encoding=serialization.Encoding.Raw)


def b64(b): return base64.b64encode(b).decode()
def unb64(s): return base64.b64decode(s)


def hkdf(key, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(key)


def derive(password, salt, iterations):
    master = PBKDF2HMAC(hashes.SHA256(), 32, salt, iterations).derive(unicodedata.normalize("NFC", password).encode())
    return hkdf(master, b"auka-auth-v1"), hkdf(master, b"auka-wrap-v1")


def pub_bytes(priv):
    return priv.public_key().public_bytes(format=serialization.PublicFormat.Raw, **RAW)


def priv_bytes(priv):
    return priv.private_bytes(format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption(), **RAW)


def wrap(wrap_key, priv_raw, pub_raw, nonce=None):
    nonce = nonce or os.urandom(12)
    return nonce + ChaCha20Poly1305(wrap_key).encrypt(nonce, priv_raw, b"auka-identity-v1" + pub_raw)


def unwrap(wrap_key, blob, pub_raw):
    return ChaCha20Poly1305(wrap_key).decrypt(blob[:12], blob[12:], b"auka-identity-v1" + pub_raw)


def message_key(my_priv_raw, peer_pub_raw):
    my = X25519PrivateKey.from_private_bytes(my_priv_raw)
    shared = my.exchange(X25519PublicKey.from_public_bytes(peer_pub_raw))
    lo, hi = sorted([pub_bytes(my), peer_pub_raw])
    return hkdf(shared, b"auka-msg-v1" + lo + hi)


def pad(data):
    return data + b" " * (-len(data) % 256)


def seal(my_priv_raw, peer_pub_raw, sender_id, recipient_id, client_id, kind, text, nonce=None):
    nonce = nonce or os.urandom(12)
    my_pub = pub_bytes(X25519PrivateKey.from_private_bytes(my_priv_raw))
    plain = pad(json.dumps({"k": kind, "t": text}, ensure_ascii=False, separators=(",", ":")).encode())
    aad = f"auka-msg-v1|{sender_id}|{recipient_id}|{client_id}".encode()
    ct = ChaCha20Poly1305(message_key(my_priv_raw, peer_pub_raw)).encrypt(nonce, plain, aad)
    return json.dumps({"v": 1, "s": b64(my_pub), "r": b64(peer_pub_raw), "n": b64(nonce), "c": b64(ct)}, separators=(",", ":"))


def open_envelope(my_priv_raw, msg):
    env = json.loads(msg["envelope"])
    my_pub = pub_bytes(X25519PrivateKey.from_private_bytes(my_priv_raw))
    peer = unb64(env["r"]) if unb64(env["s"]) == my_pub else unb64(env["s"])
    aad = f"auka-msg-v1|{msg['senderId']}|{msg['recipientId']}|{msg['clientId']}".encode()
    return json.loads(ChaCha20Poly1305(message_key(my_priv_raw, peer)).decrypt(unb64(env["n"]), unb64(env["c"]), aad))


def safety_number(a, b):
    lo, hi = sorted([a, b])
    d = hashlib.sha256(lo + hi).digest()
    return " ".join(f"{int.from_bytes(d[i:i + 5], 'big') % 100000:05d}" for i in range(0, 30, 5))


def vectors(path):
    salt = bytes(range(16))
    auth, wrapk = derive("пароль Passw0rd é", salt, 1000)
    a_priv, b_priv = bytes([1] * 32), bytes([2] * 32)
    a_pub = pub_bytes(X25519PrivateKey.from_private_bytes(a_priv))
    b_pub = pub_bytes(X25519PrivateKey.from_private_bytes(b_priv))
    nonce = bytes([9] * 12)
    ids = ("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333")
    text = 'vpn://AAAA+/== "кавычки" -- \n  отступ\ttab '
    out = {
        "password": "пароль Passw0rd é", "salt": b64(salt), "iterations": 1000,
        "authKey": b64(auth), "wrapKey": b64(wrapk),
        "aPriv": b64(a_priv), "aPub": b64(a_pub), "bPriv": b64(b_priv), "bPub": b64(b_pub),
        "wrapped": b64(wrap(wrapk, a_priv, a_pub, nonce)), "messageKey": b64(message_key(a_priv, b_pub)),
        "senderId": ids[0], "recipientId": ids[1], "clientId": ids[2], "kind": "code", "text": text,
        "envelope": seal(a_priv, b_pub, ids[0], ids[1], ids[2], "code", text, nonce),
        "safetyNumber": safety_number(a_pub, b_pub),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)


class Client:
    def __init__(self, base, nick):
        self.base, self.nick = base, nick
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname, self.ctx.verify_mode = False, ssl.CERT_NONE
        self.email = f"{nick}@example.com"
        self.password = "Correct horse " + nick
        self.token = None

    def call(self, method, path, body=None, expect=200):
        req = urllib.request.Request(self.base + "/api/v1" + path, method=method,
                                     data=None if body is None else json.dumps(body).encode())
        if self.token: req.add_header("Authorization", "Bearer " + self.token)
        try:
            with urllib.request.urlopen(req, context=self.ctx) as r:
                status, raw = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        assert status == expect, (method, path, status, raw[:300])
        return json.loads(raw) if raw else None

    def register(self):
        self.priv = os.urandom(32)
        self.pub = pub_bytes(X25519PrivateKey.from_private_bytes(self.priv))
        salt = os.urandom(16)
        auth, wrapk = derive(self.password, salt, ITER)
        r = self.call("POST", "/auth/register", dict(
            email=self.email, nickname=self.nick, displayName=self.nick, authKey=b64(auth), kdfSalt=b64(salt),
            kdfIterations=ITER, publicKey=b64(self.pub), wrappedPrivateKey=b64(wrap(wrapk, self.priv, self.pub))))
        self.token, self.id = r["token"], r["user"]["id"]

    def login_on_new_device(self):
        """Everything is rebuilt from the password alone, as on a new phone."""
        self.token, self.priv = None, None
        p = self.call("POST", "/auth/prelogin", dict(email=self.email))
        auth, wrapk = derive(self.password, unb64(p["kdfSalt"]), p["kdfIterations"])
        r = self.call("POST", "/auth/login", dict(email=self.email, authKey=b64(auth)))
        self.token = r["token"]
        self.priv = unwrap(wrapk, unb64(r["wrappedPrivateKey"]), unb64(r["user"]["publicKey"]))

    def send(self, peer_id, peer_pub, kind, text):
        cid = str(uuid.uuid4())
        env = seal(self.priv, peer_pub, self.id, peer_id, cid, kind, text)
        return self.call("POST", "/messages", dict(recipientId=peer_id, clientId=cid, envelope=env))

    def sync(self):
        return self.call("GET", "/sync")["messages"]


def main():
    if sys.argv[1] == "--vectors":
        return vectors(sys.argv[2])
    base = sys.argv[1]
    suffix = uuid.uuid4().hex[:6]
    a, b, c = (Client(base, f"{n}_{suffix}") for n in ("anna", "boris", "clara"))
    for x in (a, b, c): x.register()

    found = a.call("GET", f"/users/by-nickname/{b.nick}")
    assert unb64(found["publicKey"]) == b.pub and "email" not in found
    a.call("POST", "/contacts", dict(userId=b.id))

    key = "vpn://" + base64.b64encode(os.urandom(6000)).decode() + "  \n trailing"
    a.send(b.id, b.pub, "code", key)
    a.send(b.id, b.pub, "text", "Привет! 👋")

    got = [open_envelope(b.priv, m) for m in b.sync()]
    assert got[0] == {"k": "code", "t": key}, "code block must survive byte for byte"
    assert got[1]["t"] == "Привет! 👋"
    assert open_envelope(a.priv, a.sync()[0])["t"] == key, "sender reads their own message"

    assert c.sync() == [], "outsider sees nothing"
    raw = json.dumps(b.sync())
    assert "Привет" not in raw and "vpn://" not in raw, "server must hold only ciphertext"
    try:
        open_envelope(c.priv, b.sync()[0])
        raise SystemExit("outsider decrypted a message")
    except Exception as e:
        assert type(e).__name__ == "InvalidTag", e

    tampered = dict(b.sync()[0]); tampered["senderId"] = c.id
    try:
        open_envelope(b.priv, tampered)
        raise SystemExit("re-attributed message accepted")
    except Exception as e:
        assert type(e).__name__ == "InvalidTag", e

    a.login_on_new_device()
    assert open_envelope(a.priv, a.sync()[0])["t"] == key, "history readable after login on a new device"

    b.call("POST", "/contacts", dict(userId=a.id))
    assert a.call("POST", f"/rings/{b.id}")["seconds"] == 20
    assert a.call("POST", f"/rings/{b.id}", expect=429)["error"] == "ring_cooldown"

    first = a.sync()[0]
    b.call("DELETE", f"/messages/{first['id']}", expect=204)
    gone = next(m for m in a.sync() if m["id"] == first["id"])
    assert gone["deleted"] is True and gone["envelope"] is None

    print("E2E OK")
    if "--load" in sys.argv:
        n = int(sys.argv[sys.argv.index("--load") + 1])
        t = time.time()
        for i in range(n):
            a.call("GET", "/sync")
            if i % 2 == 0:
                cid = str(uuid.uuid4())
                # Goes through the same limiter as real users, so slow down rather than fail.
                try:
                    a.call("POST", "/messages", dict(recipientId=b.id, clientId=cid, envelope=seal(a.priv, b.pub, a.id, b.id, cid, "text", "x" * 500)))
                except AssertionError:
                    pass
        print(f"{n} rounds in {time.time() - t:.1f}s")


if __name__ == "__main__":
    main()
