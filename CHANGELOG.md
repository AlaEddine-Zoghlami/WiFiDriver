# Changelog

## v0.3.1 — 2026-06-10

First tagged release of **WiFiDriver** — a userspace **station-mode driver for the RTL8812AU**,
extracted from devourer into a standalone static library.

### Highlights
- Userspace RTL8812AU bring-up and station connect: scan → auth → assoc → WPA2 4-way handshake →
  key install → connected, alongside monitor-mode injection TX and a station data path.
- Robust connect: `libusb_reset_device` on open to clear stale device state.
- TX correctness: `FIRST_SEG` set in the monitor TX descriptor (root cause of on-air silence);
  TX power set on the station connect path.
- Packaged as a static library; consumers must link with `--whole-archive` so static-init
  translation units (and thus TX) aren't dropped.

Pairs with **devourer** (capability + JNI layer) and **PixelPilot** (the Android FPV app).
