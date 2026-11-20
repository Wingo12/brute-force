#!/usr/bin/env python3
# =============================================================================
#  Brute Force Password Tool
# =============================================================================
#  License : GNU General Public License v3.0 (GPLv3)
#  Author  : Wingo12 (Wingo123)
#  Project : https://github.com/Wingo12/brute-force
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.
# =============================================================================

"""
WPA/WPA2 cracking on pure Python.
Supports: PMKID (hc22000 WPA*01), EAPOL (hc22000 WPA*02), raw pcap/pcapng.
"""

import hmac
from hashlib import pbkdf2_hmac, sha1

from scapy.all import PcapReader, Dot11, EAPOL
from scapy.layers.dot11 import Dot11Elt


# ============================================================
# Криптография WPA
# ============================================================

def calculate_pmk(ssid: bytes, password: str) -> bytes:
    """PMK = PBKDF2-HMAC-SHA1(password, ssid, 4096, 32)"""
    return pbkdf2_hmac('sha1', password.encode('utf-8'), ssid, 4096, 32)


def calculate_pmkid(pmk: bytes, mac_ap: bytes, mac_sta: bytes) -> bytes:
    """PMKID = HMAC-SHA1(PMK, "PMK Name" + MAC_AP + MAC_STA)[:16]"""
    return hmac.new(pmk, b"PMK Name" + mac_ap + mac_sta, sha1).digest()[:16]


def _prf512(key: bytes, label: bytes, data: bytes) -> bytes:
    """PRF-512 for PTK derivation."""
    result = b''
    for i in range(4):
        result += hmac.new(key, label + b'\x00' + data + bytes([i]), sha1).digest()
    return result[:64]


def calculate_ptk(pmk: bytes, mac_ap: bytes, mac_sta: bytes,
                  nonce_ap: bytes, nonce_sta: bytes) -> bytes:
    """PTK = PRF-512(PMK, "Pairwise key expansion", min/max MACs + min/max Nonces)"""
    label = b"Pairwise key expansion"
    min_mac, max_mac = sorted([mac_ap, mac_sta])
    min_nonce, max_nonce = sorted([nonce_ap, nonce_sta])
    data = min_mac + max_mac + min_nonce + max_nonce
    return _prf512(pmk, label, data)


def verify_pmkid(password: str, ssid: bytes, mac_ap: bytes,
                 mac_sta: bytes, target_pmkid: bytes) -> bool:
    pmk = calculate_pmk(ssid, password)
    computed = calculate_pmkid(pmk, mac_ap, mac_sta)
    return hmac.compare_digest(computed, target_pmkid)


def _mic_offset_for_descriptor(eapol_raw: bytes) -> int | None:
    """
    Определяет смещение MIC по Key Descriptor Type.
    Стандартный заголовок EAPOL-Key: descriptor_type(1) + key_info(2) + key_len(2) +
    replay(8) + nonce(32) + iv(16) + rsc(8) + id(8) = 81 байт от начала EAPOL.
    """
    if len(eapol_raw) < 99:
        return None
    return 81


def verify_eapol_mic(password: str, ssid: bytes, mac_ap: bytes, mac_sta: bytes,
                     nonce_ap: bytes, nonce_sta: bytes,
                     eapol_frame: bytes, target_mic: bytes) -> bool:
    """Verify password against EAPOL MIC."""
    pmk = calculate_pmk(ssid, password)
    ptk = calculate_ptk(pmk, mac_ap, mac_sta, nonce_ap, nonce_sta)
    kck = ptk[:16]

    mic_off = _mic_offset_for_descriptor(eapol_frame)
    if mic_off is None:
        return False

    eapol_copy = bytearray(eapol_frame)
    if len(eapol_copy) >= mic_off + 16:
        eapol_copy[mic_off:mic_off + 16] = b'\x00' * 16

    computed_mic = hmac.new(kck, bytes(eapol_copy), sha1).digest()[:16]
    return hmac.compare_digest(computed_mic, target_mic)


# ============================================================
# Парсинг hc22000
# ============================================================

def parse_hc22000_line(line: str) -> dict | None:
    parts = line.strip().split('*')
    if len(parts) < 6 or parts[0] != 'WPA':
        return None

    if parts[1] == '01':
        return {
            'type': 'PMKID',
            'pmkid': bytes.fromhex(parts[2]),
            'mac_ap': bytes.fromhex(parts[3]),
            'mac_sta': bytes.fromhex(parts[4]),
            'essid': bytes.fromhex(parts[5]),
        }
    elif parts[1] == '02':
        return {
            'type': 'EAPOL',
            'mic': bytes.fromhex(parts[2]),
            'mac_ap': bytes.fromhex(parts[3]),
            'mac_sta': bytes.fromhex(parts[4]),
            'essid': bytes.fromhex(parts[5]),
            'nonce_ap': bytes.fromhex(parts[6]),
            'eapol': bytes.fromhex(parts[7]),
            'mp': parts[8] if len(parts) > 8 else '',
        }
    return None


# ============================================================
# Парсинг raw pcap / pcapng
# ============================================================

def _extract_ssid(pkt) -> bytes | None:
    """Извлекает SSID из Beacon/Probe Response."""
    if not pkt.haslayer(Dot11Elt):
        return None
    elt = pkt[Dot11Elt]
    while elt:
        if elt.ID == 0 and elt.info:
            return bytes(elt.info)
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def parse_pcap_handshakes(path: str) -> list[dict]:
    """
    Извлекает PMKID и EAPOL-цели из raw pcap/pcapng.
    Двухпроходный алгоритм с PcapReader (потоково).
    """
    # ---- Проход 1: BSSID -> SSID ----
    bssid_to_ssid = {}
    try:
        with PcapReader(path) as reader:
            for pkt in reader:
                if not pkt.haslayer(Dot11):
                    continue
                dot11 = pkt[Dot11]
                if dot11.type == 0 and dot11.subtype in (5, 8):
                    ssid = _extract_ssid(pkt)
                    if ssid and dot11.addr2:
                        bssid_to_ssid[dot11.addr2.lower()] = ssid
    except Exception as e:
        raise RuntimeError(f"Ошибка чтения pcap (проход 1): {e}")

    # ---- Проход 2: PMKID + EAPOL ----
    results = []
    anonce_map = {}
    eapol_msg2 = []

    try:
        with PcapReader(path) as reader:
            for pkt in reader:
                if not pkt.haslayer(EAPOL) or not pkt.haslayer(Dot11):
                    continue

                dot11 = pkt[Dot11]
                eapol_raw = bytes(pkt[EAPOL])

                fc = dot11.FCfield
                to_ds = bool(fc & 0x01)
                from_ds = bool(fc & 0x02)

                if from_ds:
                    ap_mac = bytes.fromhex(dot11.addr2.replace(':', ''))
                    sta_mac = bytes.fromhex(dot11.addr1.replace(':', ''))
                elif to_ds:
                    sta_mac = bytes.fromhex(dot11.addr2.replace(':', ''))
                    ap_mac = bytes.fromhex(dot11.addr1.replace(':', ''))
                else:
                    continue

                ssid = _extract_ssid(pkt)
                if not ssid:
                    bssid_key = dot11.addr2.lower() if dot11.addr2 else ''
                    ssid = bssid_to_ssid.get(bssid_key)
                if not ssid:
                    continue

                if len(eapol_raw) < 99:
                    continue

                key_info = int.from_bytes(eapol_raw[5:7], 'big')
                is_pairwise = bool(key_info & 0x0008)
                is_install = bool(key_info & 0x0040)
                is_ack = bool(key_info & 0x0080)
                is_mic = bool(key_info & 0x0100)

                if not is_pairwise:
                    continue

                # Message 1: PMKID + ANonce
                if is_ack and not is_mic:
                    nonce_ap = eapol_raw[17:49]
                    anonce_map[(ap_mac, sta_mac, ssid)] = nonce_ap

                    key_data = eapol_raw[99:]
                    idx = key_data.find(b'\xdd\x14\x00\x0f\xac\x04')
                    if idx != -1 and len(key_data) >= idx + 6 + 16:
                        pmkid = key_data[idx + 6:idx + 6 + 16]
                        results.append({
                            'type': 'PMKID',
                            'pmkid': pmkid,
                            'mac_ap': ap_mac,
                            'mac_sta': sta_mac,
                            'essid': ssid,
                        })

                # Message 2: SNonce + MIC
                elif not is_ack and is_mic and not is_install:
                    nonce_sta = eapol_raw[17:49]
                    mic_off = _mic_offset_for_descriptor(eapol_raw)
                    if mic_off is None:
                        continue
                    mic = eapol_raw[mic_off:mic_off + 16]

                    eapol_msg2.append({
                        'mac_ap': ap_mac,
                        'mac_sta': sta_mac,
                        'essid': ssid,
                        'nonce_sta': nonce_sta,
                        'eapol': eapol_raw,
                        'mic': mic,
                    })
    except Exception as e:
        raise RuntimeError(f"Ошибка чтения pcap (проход 2): {e}")

    for m2 in eapol_msg2:
        key = (m2['mac_ap'], m2['mac_sta'], m2['essid'])
        if key in anonce_map:
            results.append({
                'type': 'EAPOL',
                'mic': m2['mic'],
                'mac_ap': m2['mac_ap'],
                'mac_sta': m2['mac_sta'],
                'essid': m2['essid'],
                'nonce_ap': anonce_map[key],
                'eapol': m2['eapol'],
                'mp': '',
            })

    return results
