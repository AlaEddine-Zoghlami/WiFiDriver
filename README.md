# WiFiDriver

A **universal userspace USB driver for the Realtek RTL8812AU** (and 8814/8821), built on
**libusb** so it runs on any host — Android (no root), Linux, Windows — doing everything through
USB control/bulk transfers, no kernel module.

It is the bottom layer of a 3-repo stack:

```
PixelPilot (app)  ──uses──▶  devourer (IP/FPV/JNI)  ──uses──▶  WiFiDriver (this repo)
```

- **WiFiDriver** (this repo) — the pure libusb driver: radio + 802.11 + **Station** and **wfb**
  (wifibroadcast) modes. No IP layer, no JNI.
- **devourer** — adds the IP layer (DHCP / **static-IP** / ARP), FPV glue (RTP, LQ), session
  management (auto-reconnect), WPA2 hardening, and the **JNI**. Depends on WiFiDriver.
  → https://github.com/AlaEddine-Zoghlami/Devourer
- **PixelPilot** — the Android FPV ground-station app. Depends on devourer.
  → https://github.com/AlaEddine-Zoghlami/PixelPilot

## What it does

- **Station mode** — scan → auth → assoc → **open _or_ WPA2-PSK** (full 4-way handshake + CCMP) →
  a decrypted L2 IP pipe. (`StationMode`, `Wpa2Supplicant`, `Wpa2Crypto`, `Dot11Frames`, `ScanProbe`.)
- **wfb mode** — the existing wifibroadcast monitor/inject + FEC path, kept verbatim.
  (`wfb/`, optional — see `WIFIDRIVER_WITH_WFB`.)
- **Radio/HAL** — PHY/RF/EEPROM/IQK/power for 8812/8814/8821, USB adapter with async-URB RX +
  sync TX. (`hal/`, `RtlUsbAdapter`, `RtlJaguarDevice`, `HalModule`, `RadioManagementModule`, …)

## Build

```sh
cmake -B build -S .                 # core driver + Station L2 (needs libusb-1.0)
cmake --build build --target WiFiDriver
```

`-DWIFIDRIVER_WITH_WFB=ON` additionally builds the wfb (wifibroadcast) mode; it needs **libsodium**
(and, on Android, the JNI/log libs). The core driver builds with only **libusb-1.0**.

## Attribution

This project incorporates and adapts code from:

- **[svpcom/wfb-ng](https://github.com/svpcom/wfb-ng)** — the wifibroadcast protocol, FEC (zfex),
  and RX/TX aggregation in `wfb/` (GPL).
- **[buldo/WiFiDriver](https://github.com/buldo/WiFiDriver)** — the original libusb RTL8812AU
  userspace driver this builds on.
- **Realtek** RTL8812AU/8814AU/8821AU HAL/PHY tables (`hal/`), via the aircrack-ng `rtl8812au` /
  `rtl8814au` trees.

See `LICENSE` and the upstream projects for license terms.
