# WiFiDriver

**The first userspace _station-mode_ driver for the Realtek RTL8812AU.**

WiFiDriver connects to a Wi-Fi access point **as a client** — scan → authenticate → associate →
(open **or** WPA2-PSK, full 4-way handshake + CCMP) → a decrypted L2 / IP pipe — running entirely
in **userspace over libusb**: no kernel module, no root. It works on any host — **Android (no root)**,
Linux, Windows.

Existing userspace RTL8812AU drivers (e.g. [buldo/WiFiDriver](https://github.com/buldo/WiFiDriver),
the [wfb-ng](https://github.com/svpcom/wfb-ng) stack) do monitor / injection for *wifibroadcast*
only. WiFiDriver adds the full **station** path on top of that foundation — to our knowledge the
first userspace station-mode implementation for this chip.

It is the bottom layer of a 3-repo stack:

```
PixelPilot (app)  ──uses──▶  devourer (IP / FPV / JNI)  ──uses──▶  WiFiDriver (this repo)
```

- **WiFiDriver** (this repo) — the pure libusb driver: radio + 802.11 + **Station** and **wfb** modes. No IP layer, no JNI.
- **devourer** — DHCP / static-IP / ARP, RTP + LQ, auto-reconnect, WPA2 hardening, and the JNI. → https://github.com/AlaEddine-Zoghlami/Devourer
- **PixelPilot** — the Android FPV ground-station app (wfb **and** APFPV station modes). → https://github.com/AlaEddine-Zoghlami/PixelPilot

## What it does

- **Station mode** — scan → auth → assoc → **open _or_ WPA2-PSK** (4-way handshake + CCMP) → a
  decrypted L2 IP pipe. (`StationMode`, `Wpa2Supplicant`, `Wpa2Crypto`, `Dot11Frames`, `ScanProbe`.)
- **wfb mode** — the existing wifibroadcast monitor/inject + FEC path, kept verbatim (`wfb/`, optional).
- **Radio / HAL** — PHY/RF/EEPROM/IQK/power for 8812/8814/8821, USB adapter with async-URB RX + sync TX.

## Build

Requires **libusb-1.0** (+ a C++20 compiler, CMake ≥ 3.15).

```sh
cmake -B build -S .
cmake --build build --target WiFiDriver        # -> libWiFiDriver.a
```

- `-DWIFIDRIVER_WITH_WFB=ON` additionally builds the wfb (wifibroadcast) mode; it needs **libsodium**.
- Windows (MSYS2/MinGW): `C:/msys64/mingw64/bin/cmake --build build` with `mingw64/bin` on `PATH`.

The driver is consumed as a library — see **devourer** for the full station + IP + FPV stack, and an
end-to-end host demo (`ApfpvCompliance`).

## Attribution

Incorporates and adapts code from **[svpcom/wfb-ng](https://github.com/svpcom/wfb-ng)** (wifibroadcast
protocol + FEC, `wfb/`, GPL), **[buldo/WiFiDriver](https://github.com/buldo/WiFiDriver)** (the original
libusb RTL8812AU userspace driver), and Realtek RTL8812AU/8814AU/8821AU HAL/PHY tables (`hal/`, via the
aircrack-ng trees). See `LICENSE` and the upstream projects for terms.
