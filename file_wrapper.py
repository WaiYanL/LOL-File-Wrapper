#!/usr/bin/env python3
"""
LOL File Wrapper — PySide6 Edition
Packs any file into a custom .lol container and unpacks it losslessly.
Supports zlib compression (level 0–9), AES-256-CTR encryption with
a user passphrase, and a custom file extension.
"""

import os
import sys
import json
import zlib
import base64
import threading
from typing import Callable, Optional
from struct import pack as _spack

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QSlider, QProgressBar,
    QFileDialog, QFrame, QGraphicsDropShadowEffect, QScrollArea,
    QSizePolicy, QCheckBox, QMessageBox,
)
from PySide6.QtCore import (
    Qt, QThread, Signal, QSize, QPropertyAnimation, QEasingCurve,
    QMimeData, QUrl,
)
from PySide6.QtGui import (
    QFont, QColor, QPainter, QPainterPath, QIcon, QPixmap,
    QDragEnterEvent, QDropEvent, QCursor, QFontDatabase, QPalette,
)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ═══════════════════════════════════════════════════════════════════════════════
# XorshiftCipher
# ═══════════════════════════════════════════════════════════════════════════════


class XorshiftCipher:
    __slots__ = ("_state", "_buffer", "_buf_pos")

    def __init__(self, key_string: str, salt: bytes):
        self._state = self._derive_seed(key_string, salt)
        self._buffer = b""
        self._buf_pos = 0

    @staticmethod
    def _derive_seed(key_string: str, salt: bytes) -> int:
        h = 14695981039346656037
        for byte in key_string.encode("utf-8") + salt:
            h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
            h ^= byte
        return h

    def _next(self) -> int:
        x = self._state
        x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
        x ^= (x >> 7) & 0xFFFFFFFFFFFFFFFF
        x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
        self._state = x
        return x

    def encrypt(self, data: bytes) -> bytes:
        result = bytearray(len(data))
        for i, byte in enumerate(data):
            if self._buf_pos >= len(self._buffer):
                self._buffer = _spack("<Q", self._next())
                self._buf_pos = 0
            result[i] = byte ^ self._buffer[self._buf_pos]
            self._buf_pos += 1
        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        return self.encrypt(data)


def _xorshift_salt(size: int = 16) -> bytes:
    return os.urandom(size)


# ═══════════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════════

CHUNK_SIZE: int = 1048576
METADATA_SIZE_LEN: int = 10
DEFAULT_EXTENSION: str = ".lol"
PBKDF2_ITERATIONS: int = 200_000
SALT_BYTES: int = 16
AES_NONCE_BYTES: int = 16
XORSHIFT_SALT_BYTES: int = 16
PARALLEL_WORKERS: int = 4


# ═══════════════════════════════════════════════════════════════════════════════
# Key Derivation
# ═══════════════════════════════════════════════════════════════════════════════


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


# ═══════════════════════════════════════════════════════════════════════════════
# Core Pack Operation
# ═══════════════════════════════════════════════════════════════════════════════


def pack_file(
    input_paths: list[str],
    output_path: str,
    compress_level: int = 0,
    password: Optional[str] = None,
    ext_name: str = "lol",
    progress_callback: Optional[Callable[[int, int], None]] = None,
    cancel_event: Optional[threading.Event] = None,
) -> None:
    encrypted: bool = bool(password)

    salt: Optional[bytes] = None
    nonce: Optional[bytes] = None
    if encrypted:
        salt = os.urandom(SALT_BYTES)
        nonce = os.urandom(AES_NONCE_BYTES)

    ext_salt: bytes = _xorshift_salt(XORSHIFT_SALT_BYTES)

    name_cipher = XorshiftCipher(ext_name, ext_salt)

    files_info: list[dict] = []
    total_size: int = 0
    for ip in input_paths:
        fsize = os.path.getsize(ip)
        total_size += fsize
        fresh_cipher = XorshiftCipher(ext_name, ext_salt)
        enc_name = base64.b64encode(
            fresh_cipher.encrypt(os.path.basename(ip).encode("utf-8"))
        ).decode("ascii")
        files_info.append({"name": enc_name, "size": fsize})

    metadata: dict = {
        "files": files_info,
        "compressed": compress_level > 0,
        "compress_level": compress_level,
        "encrypted": encrypted,
        "ext_encrypted": True,
        "ext_name": ext_name,
        "ext_salt": base64.b64encode(ext_salt).decode("ascii"),
        "name_encrypted": True,
    }
    if encrypted:
        metadata["salt"] = base64.b64encode(salt).decode("ascii")
        metadata["nonce"] = base64.b64encode(nonce).decode("ascii")

    metadata_bytes: bytes = json.dumps(metadata, ensure_ascii=False).encode("utf-8")
    if not (0 <= len(metadata_bytes) < 10**10):
        raise ValueError("Metadata too large for the 10-byte size indicator")

    size_prefix: bytes = str(len(metadata_bytes)).zfill(METADATA_SIZE_LEN).encode("ascii")

    total_chunks: int = max(1, (total_size + CHUNK_SIZE - 1) // CHUNK_SIZE)
    chunk_count: int = 0

    with open(output_path, "wb") as lol_file:
        lol_file.write(size_prefix)
        lol_file.write(metadata_bytes)

        compressor = zlib.compressobj(level=compress_level) if compress_level > 0 else None

        ext_cipher = XorshiftCipher(ext_name, ext_salt)
        transform_stages = [ext_cipher.encrypt]

        encryptor = None
        if encrypted:
            cipher = Cipher(algorithms.AES(_derive_key(password, salt)), modes.CTR(nonce))
            encryptor = cipher.encryptor()
            transform_stages.append(encryptor.update)

        for ip in input_paths:
            with open(ip, "rb") as src_file:
                while True:
                    if cancel_event is not None and cancel_event.is_set():
                        raise InterruptedError("Operation cancelled by user")

                    chunk: bytes = src_file.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    data = chunk
                    if compressor:
                        out = compressor.compress(data)
                        data = out if out else b""

                    for stage in transform_stages:
                        data = stage(data)

                    if data:
                        lol_file.write(data)

                    chunk_count += 1
                    if progress_callback is not None:
                        progress_callback(chunk_count, total_chunks)

        if compressor:
            tail: bytes = compressor.flush()
            if tail:
                data = tail
                for stage in transform_stages:
                    data = stage(data)
                lol_file.write(data)

        if encryptor:
            final = encryptor.finalize()
            if final:
                data = final
                for stage in transform_stages[1:]:
                    data = stage(data)
                lol_file.write(data)

    if cancel_event is not None and cancel_event.is_set():
        os.remove(output_path)


# ═══════════════════════════════════════════════════════════════════════════════
# Core Unpack Operation
# ═══════════════════════════════════════════════════════════════════════════════


def unpack_file(
    lol_path: str,
    output_dir: str,
    password: Optional[str] = None,
    progress_callback: Optional[Callable[[int, int], None]] = None,
    cancel_event: Optional[threading.Event] = None,
) -> list[str]:
    with open(lol_path, "rb") as lol_file:
        size_prefix: bytes = lol_file.read(METADATA_SIZE_LEN)
        if len(size_prefix) < METADATA_SIZE_LEN:
            raise ValueError("Not a valid container file: file is too small")
        try:
            metadata_len: int = int(size_prefix.decode("ascii"))
        except ValueError:
            raise ValueError("Corrupted file: invalid metadata size indicator")
        if metadata_len <= 0 or metadata_len > 10**10:
            raise ValueError("Corrupted file: metadata size out of valid range")

        metadata_bytes: bytes = lol_file.read(metadata_len)
        if len(metadata_bytes) < metadata_len:
            raise ValueError("Corrupted file: metadata truncated")
        try:
            metadata: dict = json.loads(metadata_bytes.decode("utf-8"))
        except json.JSONDecodeError:
            raise ValueError("Corrupted file: invalid metadata JSON")

        files_info: list[dict] = metadata.get("files", [])
        if not files_info:
            raise ValueError("Corrupted file: no files in archive metadata")

        compress_level: int = metadata.get("compress_level", 0)
        compressed: bool = metadata.get("compressed", False) or compress_level > 0
        encrypted: bool = metadata.get("encrypted", False)
        ext_encrypted: bool = metadata.get("ext_encrypted", False)
        name_encrypted: bool = metadata.get("name_encrypted", False)

        if encrypted and not password:
            raise ValueError("This file is encrypted. Provide a passphrase to unpack.")
        salt = None
        nonce = None
        if encrypted:
            try:
                salt = base64.b64decode(metadata["salt"])
                nonce = base64.b64decode(metadata["nonce"])
            except (KeyError, ValueError):
                raise ValueError("Corrupted container file: missing encryption parameters")

        ext_salt = None
        ext_name = None
        if ext_encrypted:
            try:
                ext_salt = base64.b64decode(metadata["ext_salt"])
                ext_name = metadata["ext_name"]
            except (KeyError, ValueError):
                raise ValueError("Corrupted container file: missing extension encryption parameters")

        total_plain_size = sum(f["size"] for f in files_info)
        total_chunks: int = max(1, (total_plain_size + CHUNK_SIZE - 1) // CHUNK_SIZE)
        chunk_count: int = 0

        transform_stages = []
        if encrypted:
            key = _derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
            decryptor = cipher.decryptor()
            transform_stages.append(decryptor.update)
        if ext_encrypted:
            ext_cipher = XorshiftCipher(ext_name, ext_salt)
            transform_stages.append(ext_cipher.decrypt)

        decompressor = None
        if compressed:
            decompressor = zlib.decompressobj()

        buf = b""
        restored_files: list[str] = []
        file_idx = 0
        file_remaining = files_info[0]["size"] if files_info else 0

        output_path = ""

        while file_idx < len(files_info):
            if cancel_event is not None and cancel_event.is_set():
                raise InterruptedError("Operation cancelled by user")

            raw = lol_file.read(CHUNK_SIZE)
            if not raw:
                if decompressor:
                    tail = decompressor.flush()
                    if tail:
                        buf += tail
                break

            data = raw
            for stage in transform_stages:
                data = stage(data)
            if decompressor:
                data = decompressor.decompress(data)
            buf += data

            while file_idx < len(files_info) and file_remaining <= len(buf):
                info = files_info[file_idx]
                if name_encrypted and ext_salt is not None and ext_name is not None:
                    try:
                        nc = XorshiftCipher(ext_name, ext_salt)
                        fname = nc.decrypt(
                            base64.b64decode(info["name"])
                        ).decode("utf-8")
                    except Exception:
                        fname = f"restored_file_{file_idx}"
                else:
                    fname = info.get("name", f"restored_file_{file_idx}")

                output_path = os.path.join(output_dir, fname)
                file_bytes = buf[:info["size"]]
                buf = buf[info["size"]:]

                with open(output_path, "wb") as out_file:
                    out_file.write(file_bytes)

                restored_files.append(output_path)
                chunk_count += 1
                if progress_callback is not None:
                    progress_callback(chunk_count, total_chunks)

                file_idx += 1
                if file_idx < len(files_info):
                    file_remaining = files_info[file_idx]["size"]

        if cancel_event is not None and cancel_event.is_set():
            for rf in restored_files:
                if os.path.exists(rf):
                    os.remove(rf)
            raise InterruptedError("Operation cancelled by user")

        if file_idx < len(files_info):
            raise ValueError(
                f"Archive incomplete: expected {len(files_info)} files, extracted {file_idx}"
            )

    return restored_files


def read_metadata(lol_path: str) -> Optional[dict]:
    try:
        with open(lol_path, "rb") as f:
            prefix = f.read(METADATA_SIZE_LEN)
            if len(prefix) < METADATA_SIZE_LEN:
                return None
            mlen = int(prefix.decode("ascii"))
            if mlen <= 0 or mlen > 10**10:
                return None
            meta_bytes = f.read(mlen)
            if len(meta_bytes) < mlen:
                return None
            return json.loads(meta_bytes.decode("utf-8"))
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Helper
# ═══════════════════════════════════════════════════════════════════════════════


def _format_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}" if unit != "B" else f"{size_bytes} B"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"




# ═══════════════════════════════════════════════════════════════════════════════
# Theme — exact colors from newui reference screens
# ═══════════════════════════════════════════════════════════════════════════════

C = {
    "bg":           "#0D0D0D",
    "card":         "#1A1A1A",
    "settings_inner":"#111111",
    "file_row":     "#151515",
    "file_row_border":"rgba(255,255,255,0.08)",
    "border":       "#2D2D2D",
    "border_subtle":"rgba(255,255,255,0.08)",
    "text1":        "#ffffff",
    "text2":        "rgba(255,255,255,0.55)",
    "text3":        "rgba(255,255,255,0.45)",
    "text4":        "rgba(255,255,255,0.35)",
    "accent":       "#10b981",
    "accent_glow":  "rgba(16,185,129,0.25)",
    "accent_dim":   "rgba(16,185,129,0.15)",
    "accent_text":  "#34d399",
    "nav_bg":       "#1A1A1A",
    "nav_border":   "rgba(255,255,255,0.10)",
    "input_bg":     "#0F0F0F",
    "settings_item":"#171717",
    "sep":          "rgba(255,255,255,0.10)",
    "hover":        "#222222",
    "slider_track": "rgba(255,255,255,0.10)",
    "overlay_bg":   "rgba(0,0,0,0.60)",
    "check_bg":     "rgba(16,185,129,0.15)",
    "check_bg2":    "rgba(16,185,129,0.25)",
    "info_box":     "#111111",
    "btn_secondary":"#2D2D2D",
    "btn_sec_border":"rgba(255,255,255,0.10)",
}


def _file_icon(ext: str) -> tuple[str, str, str]:
    ext = ext.lower()
    if ext in {".zip", ".lol", ".7z", ".rar", ".tar", ".gz"}:
        return ("Z", "#064e3b", "#00bc7d")
    if ext in {".sql", ".db", ".csv", ".json", ".xml"}:
        return ("D", "#1e3a5f", "#3b82f6")
    if ext in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"}:
        return ("I", "#4c1d95", "#a78bfa")
    return ("F", "#27272a", "#9f9fa9")


# ═══════════════════════════════════════════════════════════════════════════════
# Worker Thread
# ═══════════════════════════════════════════════════════════════════════════════


class Worker(QThread):
    progress = Signal(float)
    finished = Signal(int, int)
    error = Signal(str)

    def __init__(self, mode, files, output, compress_level, password, ext_name):
        super().__init__()
        self.mode = mode
        self.files = list(files)
        self.output = output
        self.compress_level = compress_level
        self.password = password
        self.ext_name = ext_name
        self.cancel_event = threading.Event()

    def cancel(self):
        self.cancel_event.set()

    def run(self):
        ok = 0
        fail = 0
        try:
            if self.mode == "pack":
                def cb(chunk, total_chunks):
                    self.progress.emit(chunk / max(total_chunks, 1))
                pack_file(self.files, self.output, compress_level=self.compress_level,
                          password=self.password, ext_name=self.ext_name,
                          progress_callback=cb, cancel_event=self.cancel_event)
                ok = 1
            elif self.mode == "pack_individual":
                total = len(self.files)
                for i, fp in enumerate(self.files):
                    try:
                        stem = os.path.splitext(os.path.basename(fp))[0]
                        dst = os.path.join(self.output, f"{stem}.{self.ext_name}")
                        def cb(chunk, total_chunks, idx=i, t=total):
                            self.progress.emit((idx + chunk / max(total_chunks, 1)) / t)
                        pack_file([fp], dst, compress_level=self.compress_level,
                                  password=self.password, ext_name=self.ext_name,
                                  progress_callback=cb, cancel_event=self.cancel_event)
                        ok += 1
                    except InterruptedError:
                        fail += 1
                    except Exception as ex:
                        self.error.emit(str(ex))
                        fail += 1
            else:
                total = len(self.files)
                for i, fp in enumerate(self.files):
                    try:
                        def cb(chunk, total_chunks, idx=i, t=total):
                            self.progress.emit((idx + chunk / max(total_chunks, 1)) / t)
                        unpack_file(fp, self.output, password=self.password,
                                    progress_callback=cb, cancel_event=self.cancel_event)
                        ok += 1
                    except InterruptedError:
                        fail += 1
                    except Exception as ex:
                        self.error.emit(str(ex))
                        fail += 1
        except InterruptedError:
            fail += 1
        except Exception as ex:
            self.error.emit(str(ex))
            fail += 1
        self.finished.emit(ok, fail)


# ═══════════════════════════════════════════════════════════════════════════════
# Custom Widgets
# ═══════════════════════════════════════════════════════════════════════════════


class ToggleSwitch(QWidget):
    toggled = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._checked = False
        self.setFixedSize(44, 24)
        self.setCursor(QCursor(Qt.PointingHandCursor))

    def isChecked(self):
        return self._checked

    def setChecked(self, checked):
        self._checked = checked
        self.toggled.emit(checked)
        self.update()

    def mousePressEvent(self, event):
        self.setChecked(not self._checked)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        if self._checked:
            p.setBrush(QColor(C["accent"]))
            p.setPen(Qt.NoPen)
            p.drawRoundedRect(0, 0, 44, 24, 12, 12)
            p.setBrush(QColor("white"))
            p.drawEllipse(26, 4, 16, 16)
        else:
            p.setBrush(QColor("#333333"))
            p.setPen(Qt.NoPen)
            p.drawRoundedRect(0, 0, 44, 24, 12, 12)
            p.setBrush(QColor("#888888"))
            p.drawEllipse(4, 4, 16, 16)
        p.end()


class DropZone(QFrame):
    files_dropped = Signal(list)
    clicked = Signal()

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setAttribute(Qt.WA_Hover)
        self.setMinimumHeight(180)
        self.setObjectName("dropzone")
        self.setCursor(QCursor(Qt.PointingHandCursor))
        self._apply_style(False)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(6)

        icon_label = QLabel("+")
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setStyleSheet(f"font-size: 64px; font-weight: 200; font-family: 'Segoe UI', 'Helvetica Neue', sans-serif; color: {C['accent']}; background: transparent; border: none; margin-bottom: -10px;")
        layout.addWidget(icon_label)

        title = QLabel("Drag & drop files here")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(f"font-size: 15px; font-weight: bold; color: {C['text1']}; background: transparent; border: none;")
        layout.addWidget(title)

        subtitle = QLabel("or click to browse")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet(f"font-size: 13px; color: {C['text2']}; background: transparent; border: none; margin-bottom: 8px;")
        layout.addWidget(subtitle)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit()

    def enterEvent(self, event):
        self._apply_style(True)

    def leaveEvent(self, event):
        self._apply_style(False)

    def _apply_style(self, hover: bool):
        if hover:
            bg = C["hover"]
            dash = C["accent"]
        else:
            bg = C["input_bg"]
            dash = C["border"]
        self.setStyleSheet(f"QFrame#dropzone {{ border: 2px dashed {dash}; border-radius: 12px; background: {bg}; }}")

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._apply_style(True)

    def dragLeaveEvent(self, event):
        self._apply_style(False)

    def dropEvent(self, event: QDropEvent):
        self._apply_style(False)
        paths = [url.toLocalFile() for url in event.mimeData().urls() if os.path.isfile(url.toLocalFile())]
        if paths:
            self.files_dropped.emit(paths)


class FileRow(QFrame):
    remove_clicked = Signal(str)

    def __init__(self, filepath: str):
        super().__init__()
        self.filepath = filepath
        self.setStyleSheet(f"FileRow {{ background: {C['file_row']}; border-radius: 10px; border: 1px solid {C['file_row_border']}; }}")
        self.setFixedHeight(64)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 8, 14, 8)
        layout.setSpacing(12)

        basename = os.path.basename(filepath)
        ext = os.path.splitext(basename)[1]
        letter, icon_bg, icon_clr = _file_icon(ext)
        size_str = _format_size(os.path.getsize(filepath))

        icon_label = QLabel(letter)
        icon_label.setFixedSize(38, 38)
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setStyleSheet(f"background: {icon_bg}; color: {icon_clr}; border-radius: 8px; font-weight: bold; font-size: 14px;")
        layout.addWidget(icon_label)

        info = QVBoxLayout()
        info.setSpacing(2)
        name_lbl = QLabel(basename)
        name_lbl.setStyleSheet(f"color: {C['text1']}; font-weight: 600; font-size: 13px; background: transparent; border: none;")
        name_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        info.addWidget(name_lbl)
        size_lbl = QLabel(size_str)
        size_lbl.setStyleSheet(f"color: {C['text2']}; font-size: 12px; background: transparent; border: none;")
        info.addWidget(size_lbl)
        layout.addLayout(info, 1)

        rm_btn = QPushButton("\u2715")
        rm_btn.setFixedSize(28, 28)
        rm_btn.setCursor(QCursor(Qt.PointingHandCursor))
        rm_btn.setStyleSheet(f"QPushButton {{ background: transparent; color: {C['text3']}; border: none; border-radius: 14px; font-size: 13px; font-weight: bold; }} QPushButton:hover {{ background: {C['hover']}; color: {C['text1']}; }}")
        rm_btn.clicked.connect(lambda: self.remove_clicked.emit(filepath))
        layout.addWidget(rm_btn, alignment=Qt.AlignRight | Qt.AlignVCenter)


class NavPill(QWidget):
    mode_changed = Signal(str)

    def __init__(self):
        super().__init__()
        self._mode = "pack"
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(0)
        self.setFixedHeight(44)
        self.setStyleSheet(f"""
            QWidget {{
                background: {C['nav_bg']};
                border: 1px solid {C['nav_border']};
                border-radius: 22px;
            }}
        """)

        self.pack_btn = QPushButton("Pack")
        self.unpack_btn = QPushButton("Unpack")
        for btn in (self.pack_btn, self.unpack_btn):
            btn.setFixedHeight(34)
            btn.setCursor(QCursor(Qt.PointingHandCursor))
            btn.setStyleSheet("background: transparent; border: none; border-radius: 17px; padding: 0 28px; font-size: 13px; font-weight: 600;")
            layout.addWidget(btn)

        self.pack_btn.clicked.connect(lambda: self.set_mode("pack"))
        self.unpack_btn.clicked.connect(lambda: self.set_mode("unpack"))
        self._update_styles()

    def set_mode(self, mode: str):
        self._mode = mode
        self._update_styles()
        self.mode_changed.emit(mode)

    def _update_styles(self):
        if self._mode == "pack":
            self.pack_btn.setStyleSheet(f"QPushButton {{ background: {C['accent']}; color: white; font-weight: 700; border: none; border-radius: 17px; padding: 0 28px; font-size: 13px; }} QPushButton:pressed {{ background: #059669; }}")
            self.unpack_btn.setStyleSheet(f"QPushButton {{ background: transparent; color: {C['text2']}; border: none; border-radius: 17px; padding: 0 28px; font-size: 13px; font-weight: 600; }} QPushButton:hover {{ color: #ffffff; }} QPushButton:pressed {{ background: rgba(255, 255, 255, 0.05); }}")
        else:
            self.pack_btn.setStyleSheet(f"QPushButton {{ background: transparent; color: {C['text2']}; border: none; border-radius: 17px; padding: 0 28px; font-size: 13px; font-weight: 600; }} QPushButton:hover {{ color: #ffffff; }} QPushButton:pressed {{ background: rgba(255, 255, 255, 0.05); }}")
            self.unpack_btn.setStyleSheet(f"QPushButton {{ background: {C['accent']}; color: white; font-weight: 700; border: none; border-radius: 17px; padding: 0 28px; font-size: 13px; }} QPushButton:pressed {{ background: #059669; }}")


class SuccessOverlay(QWidget):
    back_clicked = Signal()
    open_folder = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setVisible(False)

    def show_card(self, output_dir: str):
        for w in self.findChildren(QWidget):
            w.deleteLater()
        self._build(output_dir)
        self.setVisible(True)
        self.raise_()

    def _build(self, output_dir: str):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(0, 0, 0, 0)

        card = QFrame()
        card.setFixedWidth(420)
        card.setMinimumHeight(360)
        card.setStyleSheet(f"QFrame {{ background: {C['card']}; border: 1px solid {C['border']}; border-radius: 24px; }}")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(40, 36, 40, 36)
        cl.setSpacing(16)
        cl.setAlignment(Qt.AlignCenter)

        # Checkmark circle
        check_frame = QFrame()
        check_frame.setFixedSize(72, 72)
        check_frame.setStyleSheet(f"background: {C['accent']}; border-radius: 36px;")
        cfl = QVBoxLayout(check_frame)
        cfl.setAlignment(Qt.AlignCenter)
        check_lbl = QLabel("\u2713")
        check_lbl.setAlignment(Qt.AlignCenter)
        check_lbl.setStyleSheet("color: white; font-size: 32px; font-weight: bold; background: transparent; border: none;")
        cfl.addWidget(check_lbl)
        cl.addWidget(check_frame, alignment=Qt.AlignCenter)

        title = QLabel("Pack Complete!")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(f"color: {C['text1']}; font-size: 22px; font-weight: bold; background: transparent; border: none;")
        cl.addWidget(title)

        # Info box
        info = QFrame()
        info.setStyleSheet(f"QFrame {{ background: #1E1E1E; border: 1px solid {C['border']}; border-radius: 12px; }}")
        il = QVBoxLayout(info)
        il.setContentsMargins(16, 16, 16, 16)
        il.setSpacing(8)

        for label, value in [
            ("Name", os.path.basename(output_dir) if output_dir else "Unknown"),
            ("Output Location", output_dir),
            ("Mode", "Pack"),
        ]:
            row = QHBoxLayout()
            row.setSpacing(8)
            lbl = QLabel(label)
            lbl.setStyleSheet("color: #a0a0a0; font-size: 12px; background: transparent; border: none;")
            lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            row.addWidget(lbl)
            row.addStretch()
            val = QLabel(value)
            val.setStyleSheet("color: #ffffff; font-size: 12px; background: transparent; border: none;")
            val.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            val.setWordWrap(True)
            val.setMinimumHeight(18)
            row.addWidget(val)
            il.addLayout(row)
        cl.addWidget(info)

        # Progress bar
        progress = QProgressBar()
        progress.setRange(0, 1)
        progress.setValue(1)
        progress.setTextVisible(False)
        progress.setFixedHeight(4)
        progress.setStyleSheet(f"QProgressBar {{ background: {C['border']}; border: none; border-radius: 2px; }} QProgressBar::chunk {{ background: {C['accent']}; border-radius: 2px; }}")
        pct_row = QHBoxLayout()
        pct_row.addWidget(progress, 1)
        pct_lbl = QLabel("100%")
        pct_lbl.setStyleSheet(f"color: {C['accent']}; font-size: 12px; font-weight: bold; background: transparent; border: none;")
        pct_row.addWidget(pct_lbl)
        cl.addLayout(pct_row)

        # Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        open_btn = QPushButton("Open Folder")
        open_btn.setCursor(QCursor(Qt.PointingHandCursor))
        open_btn.setFixedHeight(40)
        open_btn.setStyleSheet(f"QPushButton {{ background: {C['accent']}; color: white; border: none; border-radius: 10px; font-size: 14px; font-weight: 600; padding: 0 20px; }} QPushButton:hover {{ background: #0d9668; }}")
        open_btn.clicked.connect(self.open_folder.emit)
        btn_row.addWidget(open_btn)

        back_btn = QPushButton("Back")
        back_btn.setCursor(QCursor(Qt.PointingHandCursor))
        back_btn.setFixedHeight(40)
        back_btn.setStyleSheet(f"QPushButton {{ background: {C['btn_secondary']}; color: {C['text1']}; border: 1px solid {C['btn_sec_border']}; border-radius: 10px; font-size: 14px; font-weight: 600; padding: 0 20px; }} QPushButton:hover {{ background: {C['hover']}; }}")
        back_btn.clicked.connect(self.back_clicked.emit)
        btn_row.addWidget(back_btn)
        cl.addLayout(btn_row)

        layout.addWidget(card, alignment=Qt.AlignCenter)


# ═══════════════════════════════════════════════════════════════════════════════
# Settings Panels
# ═══════════════════════════════════════════════════════════════════════════════


def _settings_qss() -> str:
    return f"QFrame {{ background: {C['settings_inner']}; border-radius: 12px; border: 1px solid {C['border']}; }}"

def _label_qss(bold: bool = False) -> str:
    w = "600" if bold else "normal"
    return f"color: {C['text1']}; font-size: 13px; font-weight: {w}; background: transparent; border: none;"

def _sublabel_qss() -> str:
    return f"color: {C['text2']}; font-size: 11px; background: transparent; border: none;"

def _sep_qss() -> str:
    return f"background: {C['sep']}; border: none;"

def _input_qss() -> str:
    bg = C["input_bg"]
    border_color = C["border"]
    text_color = C["text1"]
    return (
        f"QLineEdit {{ padding: 8px 12px; background-color: {bg}; "
        f"border: 1px solid {border_color}; border-radius: 6px; color: {text_color}; font-size: 13px; }}"
    )

def _input_frame_qss() -> str:
    return (
        f"QFrame {{ padding: 0px; background-color: {C['input_bg']}; "
        f"border: 1px solid {C['border']}; border-radius: 6px; }}"
    )


def _make_eye_btn(on_click) -> QPushButton:
    btn = QPushButton("\U0001F441")
    btn.setFixedSize(28, 28)
    btn.setCursor(QCursor(Qt.PointingHandCursor))
    btn.setStyleSheet(f"QPushButton {{ background: transparent; color: {C['text2']}; border: none; font-size: 14px; }} QPushButton:hover {{ color: {C['text1']}; }}")
    btn.clicked.connect(on_click)
    return btn


def _make_input_field(placeholder: str, password: bool = False) -> QLineEdit:
    field = QLineEdit()
    field.setPlaceholderText(placeholder)
    if password:
        field.setEchoMode(QLineEdit.Password)
    field.setFixedHeight(36)
    field.setStyleSheet(_input_qss())
    return field


def _make_input_container(field: QLineEdit, eye_btn: QPushButton) -> QFrame:
    frame = QFrame()
    frame.setStyleSheet(_input_frame_qss())
    h = QHBoxLayout(frame)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(0)
    h.addWidget(field, 1)
    h.addWidget(eye_btn, 0, Qt.AlignRight | Qt.AlignVCenter)
    return frame


class PackSettings(QFrame):
    def __init__(self):
        super().__init__()
        self.setStyleSheet(_settings_qss())

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # ── Custom Extension (top) ──
        ext_row = QHBoxLayout()
        ext_row.setSpacing(10)
        ext_icon = QLabel("\U0001F4C4")
        ext_icon.setStyleSheet(f"font-size: 16px; background: transparent; border: none; color: {C['text2']};")
        ext_icon.setFixedWidth(24)
        ext_row.addWidget(ext_icon)

        ext_text = QVBoxLayout()
        ext_text.setSpacing(1)
        ext_title = QLabel("Custom Extension")
        ext_title.setStyleSheet(_label_qss(True))
        ext_text.addWidget(ext_title)
        ext_sub = QLabel("File extension for the packed archive")
        ext_sub.setStyleSheet(_sublabel_qss())
        ext_text.addWidget(ext_sub)
        ext_row.addLayout(ext_text, 1)
        layout.addLayout(ext_row)

        ext_input_row = QHBoxLayout()
        ext_input_row.setContentsMargins(34, 0, 0, 0)
        self.ext_input = QLineEdit("lol")
        self.ext_input.setPlaceholderText("e.g., lol")
        self.ext_input.setFixedHeight(36)
        self.ext_input.setStyleSheet(_input_qss())
        ext_input_row.addWidget(self.ext_input)
        layout.addLayout(ext_input_row)

        # ── Separator ──
        sep0 = QFrame()
        sep0.setFixedHeight(1)
        sep0.setStyleSheet(_sep_qss())
        layout.addWidget(sep0)

        # ── Compress toggle row ──
        comp_row = QHBoxLayout()
        comp_row.setSpacing(10)
        comp_icon = QLabel("\U0001F4E6")
        comp_icon.setStyleSheet(f"font-size: 16px; background: transparent; border: none; color: {C['text2']};")
        comp_icon.setFixedWidth(24)
        comp_row.addWidget(comp_icon)

        comp_text = QVBoxLayout()
        comp_text.setSpacing(1)
        t = QLabel("Compress")
        t.setStyleSheet(_label_qss(True))
        comp_text.addWidget(t)
        s = QLabel("Reduce archive size")
        s.setStyleSheet(_sublabel_qss())
        comp_text.addWidget(s)
        comp_row.addLayout(comp_text, 1)

        self.compress_toggle = ToggleSwitch()
        comp_row.addWidget(self.compress_toggle)
        layout.addLayout(comp_row)

        # ── Compression slider row ──
        slider_row = QHBoxLayout()
        slider_row.setContentsMargins(34, 0, 0, 0)
        slider_row.setSpacing(10)
        self.comp_slider = QSlider(Qt.Horizontal)
        self.comp_slider.setRange(0, 9)
        self.comp_slider.setValue(0)
        self.comp_slider.setFixedHeight(20)
        self.comp_slider.setStyleSheet(f"""
            QSlider::groove:horizontal {{
                background: {C['slider_track']};
                height: 4px;
                border-radius: 2px;
            }}
            QSlider::handle:horizontal {{
                background: {C['accent']};
                width: 16px; height: 16px;
                margin: -6px 0;
                border-radius: 8px;
            }}
            QSlider::sub-page:horizontal {{
                background: {C['accent']};
                border-radius: 2px;
            }}
        """)
        self.comp_slider.valueChanged.connect(self._on_slider)
        slider_row.addWidget(self.comp_slider, 1)
        self.comp_level_label = QLabel("level 0")
        self.comp_level_label.setFixedWidth(56)
        self.comp_level_label.setStyleSheet(f"color: {C['text1']}; font-size: 12px; font-weight: 600; background: transparent; border: none;")
        slider_row.addWidget(self.comp_level_label)
        self.slider_container = QWidget()
        self.slider_container.setLayout(slider_row)
        self.slider_container.setVisible(False)
        layout.addWidget(self.slider_container)
        self.compress_toggle.toggled.connect(lambda v: self.slider_container.setVisible(v))

        # ── Separator ──
        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(_sep_qss())
        layout.addWidget(sep)

        # ── Encrypt toggle row ──
        enc_row = QHBoxLayout()
        enc_row.setSpacing(10)
        lock_icon = QLabel("\U0001F512")
        lock_icon.setStyleSheet(f"font-size: 16px; background: transparent; border: none; color: {C['text2']};")
        lock_icon.setFixedWidth(24)
        enc_row.addWidget(lock_icon)

        enc_text = QVBoxLayout()
        enc_text.setSpacing(1)
        t2 = QLabel("Encrypt with Password")
        t2.setStyleSheet(_label_qss(True))
        enc_text.addWidget(t2)
        s2 = QLabel("Secure your archive with a passphrase")
        s2.setStyleSheet(_sublabel_qss())
        enc_text.addWidget(s2)
        enc_row.addLayout(enc_text, 1)

        self.encrypt_toggle = ToggleSwitch()
        enc_row.addWidget(self.encrypt_toggle)
        layout.addLayout(enc_row)

        # ── Password fields (under encrypt toggle) ──
        pw_container = QWidget()
        pw_layout = QVBoxLayout(pw_container)
        pw_layout.setContentsMargins(0, 0, 0, 0)
        pw_layout.setSpacing(10)

        pw_lbl1 = QLabel("Enter Passphrase")
        pw_lbl1.setStyleSheet(_sublabel_qss())
        pw_layout.addWidget(pw_lbl1)
        self.pw_input = _make_input_field("Enter passphrase", password=True)
        eye1 = _make_eye_btn(lambda: self._toggle_pw(self.pw_input))
        pw_layout.addWidget(_make_input_container(self.pw_input, eye1))

        pw_lbl2 = QLabel("Confirm Passphrase")
        pw_lbl2.setStyleSheet(_sublabel_qss())
        pw_layout.addWidget(pw_lbl2)
        self.pw_confirm = _make_input_field("Confirm passphrase", password=True)
        eye2 = _make_eye_btn(lambda: self._toggle_pw(self.pw_confirm))
        pw_layout.addWidget(_make_input_container(self.pw_confirm, eye2))

        self.pw_container = pw_container
        self.pw_container.setVisible(False)
        layout.addWidget(self.pw_container)
        self.encrypt_toggle.toggled.connect(lambda v: self.pw_container.setVisible(v))

        # ── Separator ──
        sep2 = QFrame()
        sep2.setFixedHeight(1)
        sep2.setStyleSheet(_sep_qss())
        layout.addWidget(sep2)

        # ── Bundle All toggle row ──
        bundle_row = QHBoxLayout()
        bundle_row.setSpacing(10)
        bundle_icon = QLabel("\U0001F4E6")
        bundle_icon.setStyleSheet(f"font-size: 16px; background: transparent; border: none; color: {C['text2']};")
        bundle_icon.setFixedWidth(24)
        bundle_row.addWidget(bundle_icon)

        bundle_text = QVBoxLayout()
        bundle_text.setSpacing(1)
        t3 = QLabel("Bundle All Files")
        t3.setStyleSheet(_label_qss(True))
        bundle_text.addWidget(t3)
        s3 = QLabel("Pack all files into a single archive")
        s3.setStyleSheet(_sublabel_qss())
        bundle_text.addWidget(s3)
        bundle_row.addLayout(bundle_text, 1)

        self.bundle_toggle = ToggleSwitch()
        bundle_row.addWidget(self.bundle_toggle)
        layout.addLayout(bundle_row)

    def _on_slider(self, val):
        self.comp_level_label.setText(f"level {val}")

    def _toggle_pw(self, field):
        field.setEchoMode(QLineEdit.Normal if field.echoMode() == QLineEdit.Password else QLineEdit.Password)

    def get_compress_level(self) -> int:
        return self.comp_slider.value() if self.compress_toggle.isChecked() else 0

    def get_password(self) -> Optional[str]:
        if not self.encrypt_toggle.isChecked():
            return None
        pw = self.pw_input.text()
        return pw if pw else None

    def passwords_match(self) -> bool:
        if not self.encrypt_toggle.isChecked():
            return True
        return self.pw_input.text() == self.pw_confirm.text()

    def get_ext_name(self) -> str:
        return self.ext_input.text().strip().lstrip(".") or "lol"

    def get_bundle_all(self) -> bool:
        return self.bundle_toggle.isChecked()


class UnpackSettings(QFrame):
    def __init__(self):
        super().__init__()
        self.setStyleSheet(_settings_qss())

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        lbl = QLabel("Decryption Passphrase")
        lbl.setStyleSheet(_label_qss(True))
        layout.addWidget(lbl)

        self.pw_input = _make_input_field("Enter Decryption Passphrase", password=True)
        eye = _make_eye_btn(self._toggle_pw)
        layout.addWidget(_make_input_container(self.pw_input, eye))

        self.info_label = QLabel("")
        self.info_label.setWordWrap(True)
        self.info_label.setStyleSheet(f"color: {C['text2']}; font-size: 11px; background: {C['input_bg']}; border: 1px solid {C['border']}; border-radius: 8px; padding: 8px 12px;")
        layout.addWidget(self.info_label)

    def _toggle_pw(self):
        self.pw_input.setEchoMode(
            QLineEdit.Normal if self.pw_input.echoMode() == QLineEdit.Password else QLineEdit.Password
        )

    def get_password(self) -> Optional[str]:
        pw = self.pw_input.text()
        return pw if pw else None

    def set_file_info(self, files: list[str]):
        if not files:
            self.info_label.setText("")
            return
        infos = []
        for fp in files[:3]:
            meta = read_metadata(fp)
            if meta:
                files_info = meta.get("files", [])
                count = len(files_info)
                name = f"{count} file{'s' if count != 1 else ''}"
                flags = []
                if meta.get("compressed") or meta.get("compress_level", 0) > 0:
                    flags.append("Compressed")
                if meta.get("encrypted"):
                    flags.append("Encrypted")
                infos.append(f"{name}" + (f" ({', '.join(flags)})" if flags else ""))
            else:
                infos.append(os.path.basename(fp))
        if len(files) > 3:
            infos.append(f"+{len(files) - 3} more")
        self.info_label.setText("  \u00b7  ".join(infos))


# ═══════════════════════════════════════════════════════════════════════════════
# Main Window
# ═══════════════════════════════════════════════════════════════════════════════


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowTitle("LOL File Wrapper")
        self.setMinimumSize(600, 700)
        self.resize(700, 780)
        self.setAcceptDrops(True)
        self._drag_pos = None

        self.files: list[str] = []
        self.mode = "pack"
        self.worker: Optional[Worker] = None
        self.last_output_dir = ""

        # ── Root container with rounded corners ──
        self.main_frame = QFrame()
        self.main_frame.setStyleSheet(f"QFrame {{ background: {C['bg']}; border-radius: 16px; }}")
        self.setCentralWidget(self.main_frame)
        root = QVBoxLayout(self.main_frame)
        root.setContentsMargins(1, 1, 1, 1)
        root.setSpacing(0)

        # ── Custom Title Bar ──
        title_bar = QFrame()
        title_bar.setFixedHeight(40)
        title_bar.setStyleSheet("background: transparent; border: none;")
        tb_layout = QHBoxLayout(title_bar)
        tb_layout.setContentsMargins(16, 0, 8, 0)
        tb_layout.setSpacing(8)

        # ── Logo (left corner, fits title bar) ──
        _script_dir = os.path.dirname(os.path.abspath(__file__))
        logo_path = os.path.join(_script_dir, "icon.png")
        logo_lbl = QLabel()
        if os.path.isfile(logo_path):
            logo_pix = QPixmap(logo_path)
            logo_lbl.setPixmap(logo_pix.scaled(96, 96, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo_lbl.setFixedSize(24, 24)
        logo_lbl.setScaledContents(True)
        logo_lbl.setStyleSheet("background: transparent; border: none;")
        tb_layout.addWidget(logo_lbl)

        title_lbl = QLabel("LOL File Wrapper")
        title_lbl.setStyleSheet(f"color: {C['text2']}; font-size: 12px; font-weight: 600; background: transparent; border: none;")
        tb_layout.addWidget(title_lbl)
        tb_layout.addStretch()

        self._btn_min = QPushButton("\u2013")
        self._btn_min.setFixedSize(32, 28)
        self._btn_min.setCursor(QCursor(Qt.PointingHandCursor))
        self._btn_min.setStyleSheet(f"""
            QPushButton {{ background: transparent; color: {C['text2']}; border: none; border-radius: 6px; font-size: 14px; font-weight: bold; }}
            QPushButton:hover {{ background: {C['hover']}; color: {C['text1']}; }}
        """)
        self._btn_min.clicked.connect(self.showMinimized)
        tb_layout.addWidget(self._btn_min)

        self._btn_close = QPushButton("\u2715")
        self._btn_close.setFixedSize(32, 28)
        self._btn_close.setCursor(QCursor(Qt.PointingHandCursor))
        self._btn_close.setStyleSheet(f"""
            QPushButton {{ background: transparent; color: {C['text2']}; border: none; border-radius: 6px; font-size: 13px; font-weight: bold; }}
            QPushButton:hover {{ background: #ef4444; color: white; }}
        """)
        self._btn_close.clicked.connect(self.close)
        tb_layout.addWidget(self._btn_close)

        root.addWidget(title_bar)

        # ── Content area ──
        content = QWidget()
        content.setStyleSheet("background: transparent;")
        cl = QVBoxLayout(content)
        cl.setContentsMargins(24, 8, 24, 24)
        cl.setSpacing(0)
        root.addWidget(content, 1)

        # ── Header: centered nav pill ──
        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 16)

        self.nav = NavPill()
        self.nav.setFixedWidth(260)
        self.nav.mode_changed.connect(self._switch_mode)
        header.addStretch()
        header.addWidget(self.nav)
        header.addStretch()
        cl.addLayout(header)

        # ── Scroll area ──
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setObjectName("mainScroll")
        scroll.setStyleSheet(f"""
            QScrollArea {{ background: transparent; border: none; }}
            QScrollBar:vertical {{ background: transparent; width: 6px; }}
            QScrollBar::handle:vertical {{ background: {C['border']}; border-radius: 3px; min-height: 30px; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
        """)
        cl.addWidget(scroll, 1)

        page = QWidget()
        page.setStyleSheet("background: transparent;")
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.setSpacing(20)
        scroll.setWidget(page)

        # ── Main Card ──
        self.card = QFrame()
        self.card.setObjectName("card")
        self.card.setStyleSheet(f"QFrame#card {{ border-radius: 16px; background-color: {C['card']}; border: 1px solid {C['border']}; }}")
        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(24, 20, 24, 20)
        card_layout.setSpacing(16)
        page_layout.addWidget(self.card)

        # ── Card Header ──
        hdr = QHBoxLayout()
        hdr.setSpacing(0)
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        self.card_title = QLabel("File Queue")
        self.card_title.setStyleSheet(f"color: {C['text1']}; font-size: 18px; font-weight: bold; background: transparent; border: none;")
        title_col.addWidget(self.card_title)
        self.card_subtitle = QLabel("Ready to pack and encrypt")
        self.card_subtitle.setStyleSheet(f"color: {C['text2']}; font-size: 12px; background: transparent; border: none;")
        title_col.addWidget(self.card_subtitle)
        hdr.addLayout(title_col, 1)

        self.add_btn = QPushButton("+ Add More")
        self.add_btn.setCursor(QCursor(Qt.PointingHandCursor))
        self.add_btn.setFixedHeight(32)
        self.add_btn.setStyleSheet(f"""
            QPushButton {{ background: {C['accent_dim']}; color: {C['accent']}; border: 1px solid {C['accent']}; border-radius: 8px; font-size: 12px; font-weight: 600; padding: 0 14px; }}
            QPushButton:hover {{ background: {C['accent']}; color: white; }}
        """)
        self.add_btn.clicked.connect(self._add_files)
        hdr.addWidget(self.add_btn, alignment=Qt.AlignRight)
        card_layout.addLayout(hdr)

        # ── Drop Zone ──
        self.drop_zone = DropZone()
        self.drop_zone.files_dropped.connect(self._add_dropped_files)
        self.drop_zone.clicked.connect(self._add_files)
        card_layout.addWidget(self.drop_zone)

        # ── File list ──
        self.file_list_widget = QWidget()
        self.file_list_widget.setStyleSheet("background: transparent;")
        self.file_list_layout = QVBoxLayout(self.file_list_widget)
        self.file_list_layout.setContentsMargins(0, 0, 0, 0)
        self.file_list_layout.setSpacing(6)
        self.file_list_layout.addStretch()
        card_layout.addWidget(self.file_list_widget)
        self.file_list_widget.setVisible(False)

        # ── Settings ──
        self.settings_container = QWidget()
        self.settings_container.setStyleSheet("background: transparent;")
        self.settings_layout = QVBoxLayout(self.settings_container)
        self.settings_layout.setContentsMargins(0, 0, 0, 0)
        self.settings_layout.setSpacing(0)
        card_layout.addWidget(self.settings_container)

        self.pack_settings = PackSettings()
        self.unpack_settings = UnpackSettings()
        self.settings_layout.addWidget(self.pack_settings)
        self.settings_layout.addWidget(self.unpack_settings)
        self.unpack_settings.setVisible(False)

        # ── Separator ──
        sep2 = QFrame()
        sep2.setFixedHeight(1)
        sep2.setStyleSheet(_sep_qss())
        card_layout.addWidget(sep2)

        # ── Footer ──
        footer = QHBoxLayout()
        footer.setSpacing(0)
        self.status_lbl = QLabel("No files selected")
        self.status_lbl.setStyleSheet(f"color: {C['text2']}; font-size: 12px; background: transparent; border: none;")
        footer.addWidget(self.status_lbl, 1)

        self.clear_btn = QPushButton("Clear Queue")
        self.clear_btn.setCursor(QCursor(Qt.PointingHandCursor))
        self.clear_btn.setFixedHeight(34)
        self.clear_btn.setStyleSheet(f"""
            QPushButton {{ background: transparent; color: {C['text2']}; border: 1px solid {C['border']}; border-radius: 8px; font-size: 12px; font-weight: 600; padding: 0 14px; }}
            QPushButton:hover {{ background: {C['hover']}; }}
            QPushButton:pressed {{ background: #111111; border-color: #444444; }}
        """)
        self.clear_btn.clicked.connect(self._clear_files)
        footer.addWidget(self.clear_btn)
        footer.addSpacing(8)

        self.action_btn = QPushButton("\U0001F4E6  Pack Files")
        self.action_btn.setCursor(QCursor(Qt.PointingHandCursor))
        self.action_btn.setFixedSize(QSize(160, 42))
        self._style_action_btn()
        self.action_btn.clicked.connect(self._on_action)
        footer.addWidget(self.action_btn)

        self.cancel_btn = QPushButton("\u25A0  Cancel")
        self.cancel_btn.setCursor(QCursor(Qt.PointingHandCursor))
        self.cancel_btn.setFixedSize(QSize(120, 42))
        self.cancel_btn.setStyleSheet(f"QPushButton {{ background: #ef4444; color: white; border: none; border-radius: 10px; font-size: 13px; font-weight: bold; }}")
        self.cancel_btn.clicked.connect(self._on_cancel)
        self.cancel_btn.setVisible(False)
        footer.addWidget(self.cancel_btn)
        card_layout.addLayout(footer)

        # ── Progress ──
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1000)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(4)
        self.progress_bar.setStyleSheet(f"QProgressBar {{ background: {C['border']}; border: none; border-radius: 2px; }} QProgressBar::chunk {{ background: {C['accent']}; border-radius: 2px; }}")
        self.progress_bar.setVisible(False)
        card_layout.addWidget(self.progress_bar)

        # ── Overlay ──
        self.overlay = SuccessOverlay(self)
        self.overlay.back_clicked.connect(self._hide_overlay)
        self.overlay.open_folder.connect(self._open_output_folder)

    def _style_action_btn(self):
        has_files = len(self.files) > 0
        if self.mode == "pack":
            self.action_btn.setText("Pack Files")
            if has_files:
                self.action_btn.setStyleSheet("QPushButton { background: #10b981; color: white; border: none; border-radius: 10px; font-size: 14px; font-weight: bold; } QPushButton:hover { background: #34d399; } QPushButton:pressed { background: #059669; }")
            else:
                self.action_btn.setStyleSheet(f"QPushButton {{ background: {C['settings_inner']}; color: {C['text2']}; border: none; border-radius: 10px; font-size: 14px; font-weight: bold; }}")
        else:
            self.action_btn.setText("Unpack Files")
            if has_files:
                self.action_btn.setStyleSheet("QPushButton { background: #3b82f6; color: white; border: none; border-radius: 10px; font-size: 14px; font-weight: bold; } QPushButton:hover { background: #60a5fa; } QPushButton:pressed { background: #2563eb; }")
            else:
                self.action_btn.setStyleSheet(f"QPushButton {{ background: {C['settings_inner']}; color: {C['text2']}; border: none; border-radius: 10px; font-size: 14px; font-weight: bold; }}")

    # ── File Management ────────────────────────────────────────────────

    def _add_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        if paths:
            for p in paths:
                if p not in self.files:
                    self.files.append(p)
            self._refresh_file_list()

    def _add_dropped_files(self, paths: list[str]):
        for p in paths:
            if p not in self.files:
                self.files.append(p)
        self._refresh_file_list()

    def _remove_file(self, path: str):
        if path in self.files:
            self.files.remove(path)
        self._refresh_file_list()

    def _clear_files(self):
        self.files.clear()
        self._refresh_file_list()

    def _refresh_file_list(self):
        while self.file_list_layout.count():
            item = self.file_list_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        has_files = len(self.files) > 0
        self.drop_zone.setVisible(not has_files)
        self.file_list_widget.setVisible(has_files)
        self.settings_container.setVisible(has_files)

        for fp in self.files:
            row = FileRow(fp)
            row.remove_clicked.connect(self._remove_file)
            self.file_list_layout.addWidget(row)
        self.file_list_layout.addStretch()

        self._update_status()
        self._style_action_btn()

        if self.mode == "unpack":
            self.unpack_settings.set_file_info(self.files)

    def _update_status(self):
        count = len(self.files)
        if count == 0:
            self.status_lbl.setText("No files selected")
        else:
            total = sum(os.path.getsize(f) for f in self.files)
            self.status_lbl.setText(f"{count} file{'s' if count != 1 else ''} \u00b7 {_format_size(total)} total")

    # ── Mode Switching ─────────────────────────────────────────────────

    def _switch_mode(self, mode: str):
        self.mode = mode
        self.pack_settings.setVisible(mode == "pack")
        self.unpack_settings.setVisible(mode != "pack")
        self.card_subtitle.setText("Ready to pack and encrypt" if mode == "pack" else "Drop your packed file here to unpack")
        self._clear_files()

    # ── Actions ────────────────────────────────────────────────────────

    def _on_action(self):
        if not self.files or self.worker:
            return
        if self.mode == "pack":
            self._do_pack()
        else:
            self._do_unpack()

    def _do_pack(self):
        pw = self.pack_settings.get_password()
        if self.pack_settings.encrypt_toggle.isChecked() and not self.pack_settings.passwords_match():
            QMessageBox.warning(self, "Password Mismatch", "Passwords do not match.")
            return
        ext = self.pack_settings.get_ext_name()
        bundle = self.pack_settings.get_bundle_all()

        if bundle:
            output_path, _ = QFileDialog.getSaveFileName(self, "Save Archive", f"archive.{ext}", f"LOL Archives (*.{ext})")
            if not output_path:
                return
            self.last_output_dir = os.path.dirname(output_path)
            self.worker = Worker("pack", self.files, output_path, self.pack_settings.get_compress_level(), pw, ext)
        else:
            output_dir = QFileDialog.getExistingDirectory(self, "Select Output Folder")
            if not output_dir:
                return
            self.last_output_dir = output_dir
            self.worker = Worker("pack_individual", self.files, output_dir, self.pack_settings.get_compress_level(), pw, ext)

        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self._on_error)
        self._set_running(True)
        self.worker.start()

    def _do_unpack(self):
        output_dir = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if not output_dir:
            return
        self.last_output_dir = output_dir
        self.worker = Worker("unpack", self.files, output_dir, 0, self.unpack_settings.get_password(), "lol")
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self._on_error)
        self._set_running(True)
        self.worker.start()

    def _on_cancel(self):
        if self.worker:
            self.worker.cancel()

    def _on_progress(self, pct: float):
        self.progress_bar.setValue(int(pct * 1000))

    def _on_finished(self, ok: int, fail: int):
        self._set_running(False)
        if self.worker:
            self.worker.deleteLater()
            self.worker = None
        if ok > 0 and self.mode == "pack":
            self._show_overlay()
        elif ok > 0:
            QMessageBox.information(self, "Success", f"Unpacked {ok} file(s) successfully.")
        if fail > 0:
            self.status_lbl.setText(f"{fail} file(s) failed")

    def _on_error(self, msg: str):
        QMessageBox.critical(self, "Error", msg)

    def _set_running(self, running: bool):
        self.action_btn.setVisible(not running)
        self.clear_btn.setVisible(not running)
        self.add_btn.setVisible(not running)
        self.cancel_btn.setVisible(running)
        self.progress_bar.setVisible(running)
        if not running:
            self.progress_bar.setValue(0)
        self.status_lbl.setText("Processing..." if running else ("No files selected" if not self.files else self.status_lbl.text()))

    # ── Overlay ────────────────────────────────────────────────────────

    def _show_overlay(self):
        self.overlay.show_card(self.last_output_dir)
        self.overlay.setGeometry(self.main_frame.rect())

    def _hide_overlay(self):
        self.overlay.setVisible(False)
        self._clear_files()

    def _open_output_folder(self):
        if os.path.isdir(self.last_output_dir):
            os.startfile(self.last_output_dir)

    # ── Window Events ──────────────────────────────────────────────────

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.overlay.isVisible():
            self.overlay.setGeometry(self.main_frame.rect())

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and event.position().y() < 40:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if self._drag_pos is not None and event.buttons() & Qt.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def mouseReleaseEvent(self, event):
        self._drag_pos = None

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        paths = [url.toLocalFile() for url in event.mimeData().urls() if os.path.isfile(url.toLocalFile())]
        if paths:
            self._add_dropped_files(paths)


# ═══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))

    palette = app.palette()
    palette.setColor(QPalette.Window, QColor(C["bg"]))
    palette.setColor(QPalette.WindowText, QColor(C["text1"]))
    palette.setColor(QPalette.Base, QColor(C["input_bg"]))
    palette.setColor(QPalette.AlternateBase, QColor(C["card"]))
    palette.setColor(QPalette.ToolTipBase, QColor(C["card"]))
    palette.setColor(QPalette.ToolTipText, QColor(C["text1"]))
    palette.setColor(QPalette.Text, QColor(C["text1"]))
    palette.setColor(QPalette.Button, QColor(C["settings_inner"]))
    palette.setColor(QPalette.ButtonText, QColor(C["text1"]))
    palette.setColor(QPalette.BrightText, QColor(C["accent"]))
    palette.setColor(QPalette.Highlight, QColor(C["accent"]))
    palette.setColor(QPalette.HighlightedText, QColor("white"))
    app.setPalette(palette)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())
