# tgdl:// 编解码；格式 tgdl://1/<dc>/<kind>/<loc_b64>/<fref_b64>/<size>/<name_b64>/<mime_b64>，字段与布局见 docs/GUIDE.md


from __future__ import annotations

import base64
import struct
from typing import Any

SCHEME = "tgdl"
VERSION = 1

KIND_DOCUMENT = "d"
KIND_PHOTO = "p"
KIND_WEBFILE = "w"
KIND_STRIPPED = "m"

_VALID_KINDS = {KIND_DOCUMENT, KIND_PHOTO, KIND_WEBFILE, KIND_STRIPPED}

DEFAULT_PHOTO_THUMB = "y"


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _pack_location(kind: str, loc: dict[str, Any]) -> bytes:
    if kind == KIND_DOCUMENT:
        return struct.pack(
            "<Qiqq",
            int(loc["volume_id"]) & 0xFFFFFFFFFFFFFFFF,
            int(loc["local_id"]),
            int(loc["id"]),
            int(loc["access_hash"]),
        )
    if kind == KIND_PHOTO:
        thumb = (loc.get("thumb_size") or DEFAULT_PHOTO_THUMB).encode("utf-8")
        if len(thumb) > 255:
            raise ValueError("thumb_size too long")
        return (
            struct.pack("<qq", int(loc["id"]), int(loc["access_hash"]))
            + bytes([len(thumb)])
            + thumb
        )
    if kind == KIND_WEBFILE:
        return struct.pack("<qq", int(loc["id"]), int(loc["access_hash"]))
    if kind == KIND_STRIPPED:
        blob = loc["bytes"]
        if isinstance(blob, str):
            blob = bytes.fromhex(blob)
        return struct.pack("<H", len(blob)) + blob
    raise ValueError("unknown kind: %r" % (kind,))


def _unpack_location(kind: str, raw: bytes) -> dict[str, Any]:
    if kind == KIND_DOCUMENT:
        volume_id, local_id, doc_id, access_hash = struct.unpack("<Qiqq", raw)
        return {
            "volume_id": volume_id,
            "local_id": local_id,
            "id": doc_id,
            "access_hash": access_hash,
        }
    if kind == KIND_PHOTO:
        photo_id, access_hash = struct.unpack_from("<qq", raw, 0)
        n = raw[16]
        thumb = raw[17 : 17 + n].decode("utf-8") if n else DEFAULT_PHOTO_THUMB
        return {
            "volume_id": 0,
            "local_id": 0,
            "id": photo_id,
            "access_hash": access_hash,
            "thumb_size": thumb,
        }
    if kind == KIND_WEBFILE:
        file_id, access_hash = struct.unpack("<qq", raw)
        return {"id": file_id, "access_hash": access_hash}
    if kind == KIND_STRIPPED:
        (length,) = struct.unpack("<H", raw[:2])
        return {"bytes": raw[2 : 2 + length].hex()}
    raise ValueError("unknown kind: %r" % (kind,))


def encode(spec: dict[str, Any]) -> str:
    """规格字典 -> tgdl:// 字符串。"""
    kind = spec["kind"]
    if kind not in _VALID_KINDS:
        raise ValueError("kind must be one of %s" % sorted(_VALID_KINDS))
    loc_b64 = _b64e(_pack_location(kind, spec["location"]))
    fref = spec.get("file_reference") or b""
    if isinstance(fref, str):
        fref = bytes.fromhex(fref)
    parts = [
        SCHEME + "://" + str(VERSION),
        str(int(spec["dc"])),
        kind,
        loc_b64,
        _b64e(fref) if fref else "",
        str(int(spec.get("size") or 0)),
        _b64e((spec.get("name") or "").encode("utf-8")),
        _b64e((spec.get("mime") or "").encode("utf-8")),
    ]
    return "/".join(parts)


def decode(uri: str) -> dict[str, Any]:
    """tgdl:// 字符串 -> 规格字典。"""
    text = uri.strip()
    prefix = SCHEME + "://"
    if not text.startswith(prefix):
        raise ValueError("not a tgdl uri")
    parts = text[len(prefix) :].split("/")
    if len(parts) != 8:
        raise ValueError("expected 8 fields, got %d" % len(parts))
    version = int(parts[0])
    if version != VERSION:
        raise ValueError("unsupported version %d" % version)
    dc = int(parts[1])
    kind = parts[2]
    if kind not in _VALID_KINDS:
        raise ValueError("bad kind %r" % (kind,))
    location = _unpack_location(kind, _b64d(parts[3]))
    fref = _b64d(parts[4]) if parts[4] else b""
    name = _b64d(parts[6]).decode("utf-8") if parts[6] else ""
    mime = _b64d(parts[7]).decode("utf-8") if parts[7] else ""
    return {
        "kind": kind,
        "dc": dc,
        "location": location,
        "file_reference": fref.hex(),
        "size": int(parts[5]),
        "name": name,
        "mime": mime,
        "downloader": "mtproto",
        "direct_url": None,
    }


def to_source_spec(uri_or_spec: Any) -> dict[str, Any]:
    """把 tgdl:// 字符串或规格字典统一成 fetcher.open_source 的 spec。"""
    spec = decode(uri_or_spec) if isinstance(uri_or_spec, str) else dict(uri_or_spec)
    return {
        "kind": "mtproto",
        "dc": spec["dc"],
        "location": spec["location"],
        "file_reference": spec["file_reference"],
        "size": spec.get("size") or 0,
        "mime": spec.get("mime") or "",
        "name": spec.get("name") or "",
    }


if __name__ == "__main__":
    cases = [
        {
            "kind": KIND_DOCUMENT,
            "dc": 4,
            "location": {
                "volume_id": 1234567890123456789,
                "local_id": 987654321,
                "id": 5555555555555555555,
                "access_hash": -1234567890123456789,
            },
            "file_reference": "00112233445566778899aabbccddeeff",
            "size": 734003200,
            "name": "sample.mp4",
            "mime": "video/mp4",
        },
        {
            "kind": KIND_PHOTO,
            "dc": 2,
            "location": {
                "id": 5463362498787484988,
                "access_hash": 5811201652970943340,
                "thumb_size": "y",
            },
            "file_reference": "023bfe04d2000002366b02e8744009559ff65a081474ea6ae8b800f9a1",
            "size": 4296,
            "name": "photo.jpg",
            "mime": "image/jpeg",
        },
    ]
    for demo in cases:
        uri = encode(demo)
        back = decode(uri)
        assert back["kind"] == demo["kind"]
        assert back["dc"] == demo["dc"]
        assert back["file_reference"] == demo["file_reference"]
        assert back["size"] == demo["size"]
        assert back["name"] == demo["name"]
        assert back["mime"] == demo["mime"]
        for k, v in demo["location"].items():
            assert back["location"][k] == v, (k, back["location"], demo["location"])
        print("%-2s %4d chars  %s" % (demo["kind"], len(uri), uri))
    print("roundtrip ok")
