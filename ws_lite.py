"""
Minimal RFC 6455 WebSocket — əl ilə yazılmış, YALNIZ Python standart
kitabxanası (heç bir əlavə asılılıq yoxdur — layihənin ümumi "stdlib-only"
fəlsəfəsinə uyğun, çünki hər iki tərəfi (client VƏ server) özümüz yazırıq).

QEYD: bu faylın EYNİ nüsxəsi `server/ws_lite.py`-də də saxlanılır (client
və server AYRI-AYRI yerlərə paylanır — paylaşılan paket mümkün deyil).
Birində düzəliş etsən, DİGƏRİNDƏ də et.

Nə DƏSTƏKLƏNMİR (qəsdən, RFC 6455-ə görə QANUNİ sadələşdirmə — çünki hər
iki ucu ÖZÜMÜZ yazırıq, ictimai/naməlum kliyentlərlə uzlaşma lazım deyil):
- Fraqmentasiya (FIN=0 davam frame-ləri) — §5.4: "An endpoint MUST be
  capable of handling control frames in the middle of a fragmented
  message" YALNIZ fraqmentasiya edən tərəflər üçün tələb olunur; biz heç
  vaxt fraqmentasiya ETMİRİK, ona görə buna ehtiyac yoxdur.
- Mətn (TEXT) frame-lər — yalnız BINARY (opcode 0x2) işlədilir, bütün
  ötürülən data artıq bytes formatındadır (JPEG/JSON-UTF8/fayl bytes).
- Sıxılma genişlənmələri (permessage-deflate), alt-protokol danışığı.

Nə MÜTLƏQ dəstəklənir (BURAXILA BİLMƏZ, "sadə binary keçid" görünsə də):
- Maskalama (client→server frame-lər MÜTLƏQ maskalanmalıdır, server→client
  HEÇ VAXT maskalanmamalıdır) — səhv istiqamətdə maska = səssiz korlanma,
  çökmə YOX (JPEG-lər "az-çox" açılır, tapılması çox çətin olur).
- 3 uzunluq kodlaması (7-bit / 16-bit-uzadılmış / 64-bit-uzadılmış) — JPEG
  kadrları rahatlıqla 65535 baytı keçir, 64-bit yolu ATLANMAMALIDIR.
- PING/PONG — İXTİYARİ DEYİL: INPUT kanalı operator klikləməyəndə
  dəqiqələrlə boş qala bilər; Render kimi platformaların aralıq şəbəkə
  infrastrukturu uzun-boş bağlantıları kəsə bilər. PING alanda avtomatik
  PONG cavabı bu modulun ÖZÜ tərəfindən verilir (çağıran heç nə etmir).
- Naməlum/CLOSE control frame-lərin ölçüyə görə düzgün keçilməsi — əks
  halda bir gözlənilməz frame bütün sonrakı axını səssizcə korlayır.
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
from typing import Callable

_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONTINUATION = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA


class WSError(Exception):
    """WebSocket protokol xətası (gözlənilməyən frame forması və s.)."""


class WSClosed(Exception):
    """Qarşı tərəf bağlantını bağladı (CLOSE frame və ya TCP EOF)."""


def _accept_key(client_ws_key: str) -> str:
    digest = hashlib.sha1((client_ws_key + _MAGIC).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


# --------------------------------------------------------------------------- #
# Handshake — HTTP Upgrade sorğusu/cavabı əl ilə qurulur (heç bir http.client
# WS-a xüsusi dəstək vermir, sadə mətn protokoludur).
# --------------------------------------------------------------------------- #

def build_client_handshake_request(
    host: str, path: str, extra_headers: dict | None = None
) -> tuple[bytes, str]:
    """Client-in göndərəcəyi HTTP Upgrade sorğusunu qurur.

    Qaytarır: (raw_http_bytes, sec_websocket_key) — key sonra serverin
    cavabını doğrulamaq üçün `verify_server_handshake_response`-a verilir.
    """
    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {ws_key}",
        "Sec-WebSocket-Version: 13",
    ]
    for k, v in (extra_headers or {}).items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("ascii"), ws_key


def parse_http_response_headers(raw: bytes) -> tuple[int, dict]:
    """Xam HTTP cavab başlıqlarını (status kodu, sözlük) formasına açır.

    `raw` "\\r\\n\\r\\n"-ə qədər olan tam başlıq bloku olmalıdır (body
    YOXDUR — WS handshake cavabında body olmur).
    """
    text = raw.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        raise WSError(f"Yanlış HTTP cavabı: {lines[0] if lines else '(boş)'}")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    return status, headers


def verify_server_handshake_response(status: int, headers: dict, ws_key: str) -> None:
    if status != 101:
        raise WSError(f"Server WS-a keçmədi (HTTP {status}).")
    accept = headers.get("sec-websocket-accept", "")
    if accept != _accept_key(ws_key):
        raise WSError("Sec-WebSocket-Accept uyğun gəlmir (saxta/yanlış server?).")


def parse_client_handshake_request(headers: dict) -> str:
    """Server tərəfi: gələn sorğunun WS Upgrade olduğunu doğrulayır,
    `Sec-WebSocket-Key`-i qaytarır."""
    upgrade = headers.get("upgrade", "").lower()
    connection = headers.get("connection", "").lower()
    key = headers.get("sec-websocket-key", "")
    if upgrade != "websocket" or "upgrade" not in connection or not key:
        raise WSError("WebSocket Upgrade başlıqları yoxdur/yanlışdır.")
    return key


def build_server_handshake_response(client_ws_key: str) -> bytes:
    accept = _accept_key(client_ws_key)
    lines = [
        "HTTP/1.1 101 Switching Protocols",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Accept: {accept}",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("ascii")


# --------------------------------------------------------------------------- #
# Frame encode/decode
# --------------------------------------------------------------------------- #

def encode_frame(payload: bytes, opcode: int, masked: bool) -> bytes:
    """Bir WS frame-i bytes-a kodlaşdırır (fraqmentasiya YOXDUR, FIN=1)."""
    length = len(payload)
    out = bytearray([0x80 | (opcode & 0x0F)])   # FIN=1

    mask_bit = 0x80 if masked else 0x00
    if length < 126:
        out.append(mask_bit | length)
    elif length < 65536:
        out.append(mask_bit | 126)
        out += struct.pack("!H", length)
    else:
        out.append(mask_bit | 127)
        out += struct.pack("!Q", length)

    if masked:
        mask_key = os.urandom(4)
        out += mask_key
        out += bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    else:
        out += payload
    return bytes(out)


def _read_exact(read_fn: Callable[[int], bytes], n: int) -> bytes:
    """`read_fn(n)` çağıraraq DƏQİQ n bayt toplayır (qismən oxumaları — həm
    socket.recv, həm rfile.read qismən qaytara bilər — idarə edir)."""
    if n == 0:
        return b""
    buf = bytearray()
    while len(buf) < n:
        chunk = read_fn(n - len(buf))
        if not chunk:
            raise WSClosed("Bağlantı gözlənilmədən bağlandı (EOF).")
        buf += chunk
    return bytes(buf)


class WSConnection:
    """Handshake TAMAMLANDIQDAN sonra bir WS bağlantısını təmsil edir.

    `read_fn`/`write_fn` nəqliyyat qatını təmsil edir — çağıran bunları
    öz socket-inə (client) və ya `self.rfile.read`/`self.wfile.write`-a
    (server, bax modul-səviyyəli qeyd: BUFERLİ rfile-dan oxumaq VACİBDİR,
    birbaşa connection.recv() YOX, əks halda artıq buferlənmiş baytlar
    itə bilər).

    `is_client=True`: göndərilən frame-lər maskalanır, qəbul edilənlər
    maskalanMAMALIdır. `is_client=False` (server): əksi.
    """

    def __init__(
        self,
        read_fn: Callable[[int], bytes],
        write_fn: Callable[[bytes], None],
        is_client: bool,
    ):
        self._read = read_fn
        self._write_fn = write_fn
        self._send_masked = is_client
        self._expect_masked = not is_client
        self._closed = False

    def send(self, payload: bytes) -> None:
        if self._closed:
            raise WSClosed("Bağlantı artıq bağlıdır.")
        self._write_fn(encode_frame(payload, OP_BINARY, self._send_masked))

    def recv(self) -> bytes:
        """Növbəti TAM binary mesajı qaytarır. PING/PONG şəffaf idarə
        olunur (çağırana heç vaxt göstərilmir). Bağlantı bağlanıbsa
        (CLOSE frame və ya EOF) WSClosed atır."""
        while True:
            try:
                header = _read_exact(self._read, 2)
            except WSClosed:
                self._closed = True
                raise
            b0, b1 = header[0], header[1]
            fin = bool(b0 & 0x80)
            opcode = b0 & 0x0F
            masked = bool(b1 & 0x80)
            length = b1 & 0x7F

            print(f"[ws-debug] recv header={header.hex()} fin={fin} opcode={opcode} masked={masked} length7={length} is_client={not self._expect_masked}")

            if not fin:
                raise WSError("Fraqmentasiya edilmiş frame alındı — dəstəklənmir.")
            if masked != self._expect_masked:
                raise WSError(f"Gözlənilməyən maskalama vəziyyəti (masked={masked}).")

            if length == 126:
                length = struct.unpack("!H", _read_exact(self._read, 2))[0]
            elif length == 127:
                length = struct.unpack("!Q", _read_exact(self._read, 8))[0]

            mask_key = _read_exact(self._read, 4) if masked else None
            payload = _read_exact(self._read, length)
            if mask_key:
                payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

            if opcode == OP_PING:
                try:
                    self._write_fn(encode_frame(payload, OP_PONG, self._send_masked))
                except Exception:
                    pass
                continue
            if opcode == OP_PONG:
                continue
            if opcode == OP_CLOSE:
                self._closed = True
                raise WSClosed("Qarşı tərəf CLOSE frame göndərdi.")
            if opcode == OP_BINARY:
                return payload
            if opcode == OP_TEXT:
                return payload
            raise WSError(f"Dəstəklənməyən/gözlənilməyən opcode: {opcode}")

    def ping(self) -> None:
        if not self._closed:
            self._write_fn(encode_frame(b"", OP_PING, self._send_masked))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._write_fn(encode_frame(b"", OP_CLOSE, self._send_masked))
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Yüksək-səviyyəli əlaqələndiricilər
# --------------------------------------------------------------------------- #

def client_handshake(
    read_fn: Callable[[int], bytes],
    write_fn: Callable[[bytes], None],
    host: str,
    path: str,
    extra_headers: dict | None = None,
) -> WSConnection:
    """Client tərəfi: TCP/TLS ARTIQ QURULMUŞ bir bağlantı üzərində WS
    handshake-i tam icra edir, hazır `WSConnection` qaytarır.

    `read_fn`/`write_fn` çağıranın öz socket-inə bağlıdır (adətən
    `sock.recv`/`sock.sendall`, `wss://` üçün TLS-wrap edilmiş socket).
    """
    request, ws_key = build_client_handshake_request(host, path, extra_headers)
    write_fn(request)

    # Başlıq bloku "\r\n\r\n"-ə qədər, bayt-bayt oxunur (TCP mesaj
    # sərhədini qorumur — bir tək read_fn() çağırışı handshake-dən sonrakı
    # WS frame baytlarını da "uda" bilər, elə bu layihədə əvvəllər
    # tapılmış eyni bug sinfi).
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        b = read_fn(1)
        if not b:
            raise WSClosed("Handshake zamanı bağlantı kəsildi.")
        buf += b
        if len(buf) > 8192:
            raise WSError("Handshake cavabı həddindən artıq böyükdür.")
    header_block = bytes(buf[: buf.index(b"\r\n\r\n")])
    status, headers = parse_http_response_headers(header_block)
    verify_server_handshake_response(status, headers, ws_key)
    return WSConnection(read_fn, write_fn, is_client=True)


def server_handshake(
    headers: dict,
    read_fn: Callable[[int], bytes],
    write_fn: Callable[[bytes], None],
) -> WSConnection:
    """Server tərəfi: gələn sorğunun (artıq oxunmuş) `headers`-indən WS-a
    keçidi tamamlayır (101 cavabını göndərir), hazır `WSConnection`
    qaytarır. `write_fn` 101 cavabını göndərmək üçün İSTİFADƏ OLUNUR —
    çağıran bunu ÖZÜ göndərməməlidir.
    """
    client_ws_key = parse_client_handshake_request(headers)
    write_fn(build_server_handshake_response(client_ws_key))
    return WSConnection(read_fn, write_fn, is_client=False)
