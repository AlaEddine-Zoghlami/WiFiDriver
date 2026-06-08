#include "RtlUsbAdapter.h"

#include <chrono>
#include <cstdlib>
#if defined(__ANDROID__) || defined(_MSC_VER) || defined(__APPLE__)
#include <libusb.h>
#else
#include <libusb-1.0/libusb.h>
#endif
#include "FrameParser.h"
#include "Hal8812PhyReg.h"
#include "logger.h"
#include <iomanip>
#include <iostream>
#include <thread>
#include <cstring>
#include <deque>
#include <mutex>
#include <condition_variable>

using namespace std::chrono_literals;

// 8812 H2C mailbox (see hal_com_reg.h). 4 boxes, 4 bytes each.
#define DEV_REG_HMETFR        0x01CC
#define DEV_REG_HMEBOX_0      0x01D0
#define DEV_REG_HMEBOX_EXT_0  0x01F0
#define DEV_H2C_BOX_SIZE      4
#define DEV_MAX_H2C_BOX       4

// Port of fill_h2c_cmd_8812 (aircrack-ng/rtl8812au hal/rtl8812a/rtl8812a_cmd.c):
// ElementID in the low byte, up to 3 payload bytes in the primary box, the rest
// in the extended box. Write EXT first, then the primary box (that triggers the
// firmware read). Round-robin the 4 boxes; wait for the box to drain first.
bool RtlUsbAdapter::fillH2CCmd(uint8_t elementID, uint32_t cmdLen,
                               const uint8_t *cmdBuffer) {
  if (cmdLen > 0 && !cmdBuffer) return false;
  if (cmdLen > 7) return false;                       // 3 primary + 4 ext
  uint8_t box = _lastH2CBox % DEV_MAX_H2C_BOX;
  // Wait until this box has been read by the FW (REG_HMETFR bit(box) == 0).
  for (int i = 0; i < 100; ++i) {
    uint8_t st = 0;
    try { st = rtw_read8(DEV_REG_HMETFR); } catch (...) { return false; }
    if ((st & (1u << box)) == 0) break;
    std::this_thread::sleep_for(1ms);
  }
  uint32_t h2c_cmd = 0, h2c_cmd_ex = 0;
  uint8_t *pc = reinterpret_cast<uint8_t *>(&h2c_cmd);
  pc[0] = elementID;
  if (cmdLen <= 3) {
    if (cmdLen) std::memcpy(pc + 1, cmdBuffer, cmdLen);
  } else {
    std::memcpy(pc + 1, cmdBuffer, 3);
    std::memcpy(&h2c_cmd_ex, cmdBuffer + 3, cmdLen - 3);
  }
  bool ok = true;
  try {
    ok &= rtw_write32((uint16_t)(DEV_REG_HMEBOX_EXT_0 + box * DEV_H2C_BOX_SIZE), h2c_cmd_ex);
    ok &= rtw_write32((uint16_t)(DEV_REG_HMEBOX_0     + box * DEV_H2C_BOX_SIZE), h2c_cmd);
  } catch (...) { ok = false; }
  _lastH2CBox = (uint8_t)((box + 1) % DEV_MAX_H2C_BOX);
  return ok;
}

RtlUsbAdapter::RtlUsbAdapter(libusb_device_handle *dev_handle, Logger_t logger)
    : _dev_handle{dev_handle}, _logger{logger} {
  libusb_device_descriptor desc{};
  if (libusb_get_device_descriptor(libusb_get_device(_dev_handle), &desc) ==
      LIBUSB_SUCCESS) {
    _idVendor = desc.idVendor;
    _idProduct = desc.idProduct;
    _logger->info("USB device {:04x}:{:04x}", _idVendor, _idProduct);
  }

  InitDvObj();

  if (usbSpeed > LIBUSB_SPEED_HIGH) // USB 3.0
  {
      rxagg_usb_size = 0x3; // 16KB
      rxagg_usb_timeout = 0x01;
  } else {
      /* the setting to reduce RX FIFO overflow on USB2.0 and increase rx
     * throughput */
      rxagg_usb_size = 0x1; // 8KB
      rxagg_usb_timeout = 0x01;
  }

  GetChipOutEP8812();

  uint8_t eeValue = rtw_read8(REG_9346CR);
  EepromOrEfuse = (eeValue & BOOT_FROM_EEPROM) != 0;
  AutoloadFailFlag = (eeValue & EEPROM_EN) == 0;

  _logger->info("Boot from {}, Autoload {} !",
                EepromOrEfuse ? "EEPROM" : "EFUSE",
                (AutoloadFailFlag ? "Fail" : "OK"));
}

/*
$ lsusb -v -d 0bda:8812
      Endpoint Descriptor:
        bLength                 7
        bDescriptorType         5
        bEndpointAddress     0x81  EP 1 IN
        bmAttributes            2
          Transfer Type            Bulk
          Synch Type               None
          Usage Type               Data
        wMaxPacketSize     0x0200  1x 512 bytes
        bInterval               0
*/

std::vector<Packet> RtlUsbAdapter::infinite_read() {
  static constexpr int BUF_SIZE = 16 * 1024;
  uint8_t buffer[BUF_SIZE] = {};
  int actual_length = 0;
  int rc;

  /* RX read timeout. A long timeout makes the sync RX monopolise libusb's event
   * handler, so a concurrent TX (auth/assoc) cannot run and times out -> station
   * mode never transmits. A short RX timeout lets RX and TX interleave.
   * DEVOURER_RX_TIMEOUT (ms) overrides; default kept long for the RX-only paths. */
  int rx_timeout = USB_TIMEOUT * 10;
  if (const char *e = std::getenv("DEVOURER_RX_TIMEOUT")) rx_timeout = std::atoi(e);
  // Yield the bus the instant a TX is pending, then hold it only for this read.
  while (_txWaiting->load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
  {
    std::lock_guard<std::mutex> lk(*_busMtx);
    rc = libusb_bulk_transfer(_dev_handle, _bulk_in_ep, buffer, sizeof(buffer),
                              &actual_length, rx_timeout);
  }
  if (rc == LIBUSB_ERROR_TIMEOUT) { return {}; }   // no data this window — normal

  if (rc < 0) {
    /* Rate-limit the error log: a fast-failing rc (e.g. LIBUSB_ERROR_NO_DEVICE
     * after the chip dropped off USB) used to spin the outer Init() loop at
     * full CPU, producing multi-GB log spam in a few seconds. Log every
     * Nth failure + sleep enough to keep the loop sane until the caller's
     * should_stop fires. */
    static uint64_t err_count = 0;
    if ((err_count++ % 100) == 0) {
      _logger->error("libusb_bulk_transfer failed with error: {} (count={})",
                     rc, err_count);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  std::vector<Packet> packets;
  FrameParser fp{_logger};
  packets =
      fp.recvbuf2recvframe(std::span<uint8_t>{buffer, (size_t)actual_length});
  return packets;
}

bool RtlUsbAdapter::WriteBytes(uint16_t reg_num, uint8_t *ptr, size_t size) {
  if (libusb_control_transfer(_dev_handle, REALTEK_USB_VENQT_WRITE, 5, reg_num,
                              0, ptr, size, USB_TIMEOUT) == size) {
    return true;
  }
  return false;
}

void RtlUsbAdapter::rtl8812au_hw_reset() {
  uint32_t reg_val = 0;

  if ((rtw_read8(REG_MCUFWDL) & BIT7) != 0) {
    _8051Reset8812();
    rtw_write8(REG_MCUFWDL, 0x00);

    /* before BB reset should do clock gated */
    rtw_write32(rFPGA0_XCD_RFPara, rtw_read32(rFPGA0_XCD_RFPara) | (BIT6));

    /* reset BB */
    reg_val = rtw_read8(REG_SYS_FUNC_EN);
    reg_val = (uint8_t)(reg_val & ~(BIT0 | BIT1));
    rtw_write8(REG_SYS_FUNC_EN, (uint8_t)reg_val);

    /* reset RF */
    rtw_write8(REG_RF_CTRL, 0);

    /* reset TRX path */
    rtw_write16(REG_CR, 0);

    /* reset MAC */
    reg_val = rtw_read8(REG_APS_FSMCO + 1);
    reg_val |= BIT1;
    rtw_write8(REG_APS_FSMCO + 1,
               (uint8_t)reg_val); /* reg0x5[1] ,auto FSM off */

    reg_val = rtw_read8(REG_APS_FSMCO + 1);

    /* check if   reg0x5[1] auto cleared */
    while ((reg_val & BIT1) != 0) {
      std::this_thread::sleep_for(1ms);
      reg_val = rtw_read8(REG_APS_FSMCO + 1);
    }

    reg_val |= BIT0;
    rtw_write8(REG_APS_FSMCO + 1,
               (uint8_t)reg_val); /* reg0x5[0] ,auto FSM on */

    reg_val = rtw_read8(REG_SYS_FUNC_EN + 1);
    reg_val = (uint8_t)(reg_val & ~(BIT4 | BIT7));
    rtw_write8(REG_SYS_FUNC_EN + 1, (uint8_t)reg_val);
    reg_val = rtw_read8(REG_SYS_FUNC_EN + 1);
    reg_val = (uint8_t)(reg_val | BIT4 | BIT7);
    rtw_write8(REG_SYS_FUNC_EN + 1, (uint8_t)reg_val);
  }
}

void RtlUsbAdapter::_8051Reset8812() {
  uint8_t u1bTmp, u1bTmp2;

  /* Reset MCU IO Wrapper- sugggest by SD1-Gimmy */
  u1bTmp2 = rtw_read8(REG_RSV_CTRL);
  rtw_write8(REG_RSV_CTRL, (uint8_t)(u1bTmp2 & (~BIT1)));
  u1bTmp2 = rtw_read8(REG_RSV_CTRL + 1);
  rtw_write8(REG_RSV_CTRL + 1, (uint8_t)(u1bTmp2 & (~BIT3)));

  u1bTmp = rtw_read8(REG_SYS_FUNC_EN + 1);
  rtw_write8(REG_SYS_FUNC_EN + 1, (uint8_t)(u1bTmp & (~BIT2)));

  /* Enable MCU IO Wrapper */
  u1bTmp2 = rtw_read8(REG_RSV_CTRL);
  rtw_write8(REG_RSV_CTRL, (uint8_t)(u1bTmp2 & (~BIT1)));
  u1bTmp2 = rtw_read8(REG_RSV_CTRL + 1);
  rtw_write8(REG_RSV_CTRL + 1, (uint8_t)(u1bTmp2 | (BIT3)));

  rtw_write8(REG_SYS_FUNC_EN + 1, (uint8_t)(u1bTmp | (BIT2)));

  _logger->info("=====> _8051Reset8812(): 8051 reset success .");
}

/*  11/16/2008 MH Read one byte from real Efuse. */
uint8_t RtlUsbAdapter::efuse_OneByteRead(uint16_t addr, uint8_t *data) {
  u32 tmpidx = 0;
  u8 bResult;
  u8 readbyte;

  /* -----------------e-fuse reg ctrl --------------------------------- */
  /* address			 */
  rtw_write8(EFUSE_CTRL + 1, (u8)(addr & 0xff));
  rtw_write8(EFUSE_CTRL + 2,
             ((u8)((addr >> 8) & 0x03)) | (rtw_read8(EFUSE_CTRL + 2) & 0xFC));

  /* rtw_write8(pAdapter, EFUSE_CTRL+3,  0x72); */ /* read cmd	 */
  /* Write bit 32 0 */
  readbyte = rtw_read8(EFUSE_CTRL + 3);
  rtw_write8(EFUSE_CTRL + 3, (readbyte & 0x7f));

  while (!(0x80 & rtw_read8(EFUSE_CTRL + 3)) && (tmpidx < 1000)) {
    std::this_thread::sleep_for(1ms);
    tmpidx++;
  }
  if (tmpidx < 100) {
    *data = rtw_read8(EFUSE_CTRL);
    bResult = true;
  } else {
    *data = 0xff;
    bResult = false;
    _logger->error("addr=0x{:x} bResult={} time out 1s !!!", addr, bResult);
    _logger->error("EFUSE_CTRL =0x{:08x} !!!", rtw_read32(EFUSE_CTRL));
  }

  return bResult;
}

void RtlUsbAdapter::ReadEFuseByte(uint16_t _offset, uint8_t *pbuf) {
  uint32_t value32;
  uint8_t readbyte;
  uint16_t retry;

  /* Match the kernel `88XXau` driver's per-iteration EFUSE_TEST clear.
   * Cold-init usbmon diff (2026-05-28, devourer-testrig VM kernel-side
   * vs host devourer-side) shows the kernel does an RD-then-WR sequence
   * at REG_EFUSE_TEST (0x0034) = 0x0000 (16-bit) BEFORE every EFUSE byte
   * read, 312 times per init; devourer never touched 0x0034. We mirror
   * the sequence so the EFUSE state machine sees identical wire shape
   * across all 312 byte reads. Empirically harmless on its own (does
   * NOT fix the RTL8814AU TX-on-air gate per a sniffer run with this
   * patch + bulk-IN drainer enabled) but removes a known concrete
   * wire-level divergence flagged by tools/usbmon_pcap_diff.py. */
  (void)rtw_read16(REG_EFUSE_TEST);
  rtw_write16(REG_EFUSE_TEST, 0x0000);

  /* Write Address */
  rtw_write8(EFUSE_CTRL + 1, (uint8_t)(_offset & 0xff));
  readbyte = rtw_read8(EFUSE_CTRL + 2);
  rtw_write8(EFUSE_CTRL + 2,
             (uint8_t)(((_offset >> 8) & 0x03) | (readbyte & 0xfc)));

  /* Write bit 32 0 */
  readbyte = rtw_read8(EFUSE_CTRL + 3);
  rtw_write8(EFUSE_CTRL + 3, (uint8_t)(readbyte & 0x7f));

  /* Check bit 32 read-ready */
  retry = 0;
  value32 = rtw_read32(EFUSE_CTRL);
  /* while(!(((value32 >> 24) & 0xff) & 0x80)  && (retry<10)) */
  while ((((value32 >> 24) & 0xff) & 0x80) == 0 && (retry < 10000)) {
    value32 = rtw_read32(EFUSE_CTRL);
    retry++;
  }

  /* 20100205 Joseph: Add delay suggested by SD1 Victor. */
  /* This fix the problem that Efuse read error in high temperature condition.
   */
  /* Designer says that there shall be some delay after ready bit is set, or the
   */
  /* result will always stay on last data we read. */

  // TODO: decide to we really need it?
  // std::this_thread::sleep_for(50ms);
  value32 = rtw_read32(EFUSE_CTRL);

  pbuf[0] = (uint8_t)(value32 & 0xff);
}

const char *RtlUsbAdapter::strUsbSpeed() {
  switch (usbSpeed) {
  case LIBUSB_SPEED_UNKNOWN:
    return "UNKNOWN";
  case LIBUSB_SPEED_LOW:
    return "1.5MBit/s";
  case LIBUSB_SPEED_FULL:
    return "12MBit/s";
  case LIBUSB_SPEED_HIGH:
    return "480MBit/s";
  case LIBUSB_SPEED_SUPER:
    return "5000MBit/s";
  case LIBUSB_SPEED_SUPER_PLUS:
    return "10000MBit/s";
  default:
    return NULL;
  }
}

void RtlUsbAdapter::InitDvObj() {
  libusb_device *dev = libusb_get_device(_dev_handle);
  usbSpeed = (enum libusb_speed)libusb_get_device_speed(dev);
  _logger->info("Running USB bus at {}", strUsbSpeed());

  libusb_device_descriptor desc;
  int ret = libusb_get_device_descriptor(dev, &desc);
  if (ret < 0) {
    return;
  }

  for (uint8_t k = 0; k < desc.bNumConfigurations; k++) {
    libusb_config_descriptor *config;
    ret = libusb_get_config_descriptor(dev, k, &config);
    if (LIBUSB_SUCCESS != ret) {
      continue;
    }

    if (!config->bNumInterfaces) {
      continue;
    }
    const libusb_interface *interface = &config->interface[0];

    if (!interface->altsetting) {
      continue;
    }
    const libusb_interface_descriptor *interface_desc =
        &interface->altsetting[0];

    bool found_bulk_in = false;
    for (uint8_t j = 0; j < interface_desc->bNumEndpoints; j++) {
      const libusb_endpoint_descriptor *endpoint = &interface_desc->endpoint[j];
      uint8_t endPointAddr = endpoint->bEndpointAddress;
      const bool is_bulk = (endpoint->bmAttributes & 0b11) ==
                           LIBUSB_ENDPOINT_TRANSFER_TYPE_BULK;
      _logger->info("endpoint[{}]: addr=0x{:X} attrs=0x{:X} bulk={} in={}",
                    (int)j, (int)endPointAddr, (int)endpoint->bmAttributes,
                    is_bulk ? 1 : 0,
                    (endPointAddr & LIBUSB_ENDPOINT_IN) ? 1 : 0);

      if (is_bulk && !(endPointAddr & LIBUSB_ENDPOINT_IN)) {
        numOutPipes++;
        _bulk_out_eps.push_back(endPointAddr);
      }
      /* First bulk IN endpoint wins. 8812AU/8814AU expose 0x81; 8821AU's
       * descriptor offers a different IN endpoint, so libusb's
       * submit_bulk_transfer to 0x81 would return "endpoint not found on any
       * open interface". Capture whatever IN endpoint the chip actually
       * exposes and use it in infinite_read(). */
      if (is_bulk && (endPointAddr & LIBUSB_ENDPOINT_IN) && !found_bulk_in) {
        _bulk_in_ep = endPointAddr;
        found_bulk_in = true;
        _logger->info("selected bulk IN endpoint: 0x{:X}", (int)_bulk_in_ep);
      }
    }
    if (!_bulk_out_eps.empty()) {
      std::string ep_list;
      for (auto ep : _bulk_out_eps) {
        char buf[8];
        snprintf(buf, sizeof(buf), "0x%02X ", ep);
        ep_list += buf;
      }
      _logger->info("bulk OUT endpoints: {}", ep_list);
    }
    /* Clear any HALT state on the bulk IN endpoint. The fwdl sequence and
     * USB reset can leave the IN EP in a stalled state from the chip side;
     * without clear_halt the chip's USB engine would never push RX bytes
     * even though the host's libusb_bulk_transfer succeeds at submission. */
    if (found_bulk_in) {
      int hr = libusb_clear_halt(_dev_handle, _bulk_in_ep);
      _logger->info("libusb_clear_halt(bulk IN 0x{:X}) rc={}", (int)_bulk_in_ep,
                    hr);
    }

    libusb_free_config_descriptor(config);
    break;
  }
}

void RtlUsbAdapter::GetChipOutEP8812() {
  OutEpQueueSel = 0;
  OutEpNumber = 0;

  switch (numOutPipes) {
  case 4:
    OutEpQueueSel = TxSele::TX_SELE_HQ | TxSele::TX_SELE_LQ |
                    TxSele::TX_SELE_NQ | TxSele::TX_SELE_EQ;
    OutEpNumber = 4;
    break;
  case 3:
    OutEpQueueSel =
        TxSele::TX_SELE_HQ | TxSele::TX_SELE_LQ | TxSele::TX_SELE_NQ;
    OutEpNumber = 3;
    break;
  case 2:
    OutEpQueueSel = TxSele::TX_SELE_HQ | TxSele::TX_SELE_NQ;
    OutEpNumber = 2;
    break;
  case 1:
    OutEpQueueSel = TxSele::TX_SELE_HQ;
    OutEpNumber = 1;
    break;
  default:
    break;
  }

  _logger->info("OutEpQueueSel({}), OutEpNumber({})", (int)OutEpQueueSel,
                (int)OutEpNumber);
}

void transfer_callback(struct libusb_transfer *transfer) {
  Logger *_logger = (Logger *)(transfer->user_data);
  if (transfer->status == LIBUSB_TRANSFER_COMPLETED &&
      transfer->actual_length == transfer->length) {
    _logger->debug("Packet {} sent successfully, length: {}", _logger,
                  transfer->length);
  } else {
    _logger->error("Failed to send packet {}, status: {}, actual length: {}",
                   _logger, transfer->status, transfer->actual_length);
  }
  libusb_free_transfer(transfer);
}

bool RtlUsbAdapter::send_packet(uint8_t *packet, size_t length) {

  libusb_transfer *transfer = libusb_alloc_transfer(0);
  if (!transfer) {
    _logger->error("Failed to allocate transfer");
    return false;
  }

  /* TX bulk OUT endpoint selection: DEVOURER_TX_EP env override > first
   * discovered OUT endpoint > historic 8812AU default (0x02). Computed
   * once on first send_packet call; captures `this` to access the
   * descriptor-walked endpoint list from InitDvObj. */
  static const uint8_t tx_ep = [this]() -> uint8_t {
    if (const char *ep_env = std::getenv("DEVOURER_TX_EP")) {
      return static_cast<uint8_t>(std::strtoul(ep_env, nullptr, 0));
    }
    if (!_bulk_out_eps.empty()) {
      return _bulk_out_eps[0];
    }
    return 0x02;
  }();

  /* On the FIRST send only, dump the bulk-OUT bytes to compare against
   * the OOT-driver wire trace. */
  static bool first_pkt_dump = true;
  if (first_pkt_dump) {
    first_pkt_dump = false;
    /* Clear any HALT state on the TX EP. The fwdl process can leave the
     * TX EP in a stalled state from the chip side; without clear_halt the
     * USB controller would NAK every subsequent bulk OUT URB. */
    int chr = libusb_clear_halt(_dev_handle, tx_ep);
    _logger->info("libusb_clear_halt(EP 0x{:02X}) rc={}", (int)tx_ep, chr);
    size_t dump_len = std::min<size_t>(length, 64);
    char hex[64 * 2 + 1] = {0};
    for (size_t k = 0; k < dump_len; ++k) {
      static const char hd[] = "0123456789abcdef";
      hex[2*k]   = hd[packet[k] >> 4];
      hex[2*k+1] = hd[packet[k] & 0xF];
    }
    _logger->info("first TX bulk-OUT len={} bytes: {}", length, hex);
  }

  /* On the FIRST send only, dump chip state via vendor reads. Surfaces any
   * register clobber between init-end and first TX (e.g. SetMonitorChannel
   * could be resetting REG_CR or related). */
  static bool first_dump = true;
  if (first_dump) {
    first_dump = false;
    uint16_t cr = rtw_read16(0x0100);
    uint8_t txpause = rtw_read8(0x0522);
    uint32_t txdma_off_chk = rtw_read32(0x020C);
    uint32_t fwhw_txq = rtw_read32(0x0420);
    uint32_t mcufwdl = rtw_read32(0x0080);
    uint32_t hci_susp = rtw_read32(0xFE10);  /* USB_HCPWM / USB suspend ctrl */
    _logger->info("pre-1st-TX: CR=0x{:04x} TXPAUSE=0x{:02x} TXDMA_OFFC=0x{:08x}",
                  cr, txpause, txdma_off_chk);
    _logger->info("pre-1st-TX: FWHW_TXQ=0x{:08x} MCUFWDL=0x{:08x} HCIPWR=0x{:08x}",
                  fwhw_txq, mcufwdl, hci_susp);
  }

  libusb_fill_bulk_transfer(transfer, _dev_handle, tx_ep, packet, length,
                            transfer_callback, (void *)(_logger.get()),
                            USB_TIMEOUT);
  /* Upstream OOT (rtl8814a/usb/rtl8814au_xmit.c) sets URB_ZERO_PACKET on
   * every TX URB. libusb equivalent: LIBUSB_TRANSFER_ADD_ZERO_PACKET.
   * Without it the chip's SuperSpeed bulk OUT controller can wait
   * indefinitely for transfer-end signaling and NAK every URB until libusb
   * cancels — matches the usbmon trace we captured: 6977 submitted URBs,
   * every completion with status=-2 (ENOENT/cancelled), data_len=0. */
  transfer->flags |= LIBUSB_TRANSFER_ADD_ZERO_PACKET;
  auto start = std::chrono::high_resolution_clock::now();
  int rc = rc = libusb_submit_transfer(transfer);
  auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double, std::milli> elapsed = end - start;
  if (rc == LIBUSB_SUCCESS) {
    _logger->debug("Packet sent successfully, length: {},used time {}ms", length,
                  elapsed.count());
    return true;
  } else {
    _logger->error("Failed to send packet, error code: {}", rc);
    libusb_free_transfer(transfer);
    return false;
  }
}

int RtlUsbAdapter::bulk_send_sync(uint8_t *packet, size_t length,
                                  int timeout_ms) {
  return bulk_send_sync_ep(0x02, packet, length, timeout_ms);
}

int RtlUsbAdapter::bulk_send_sync_ep(uint8_t ep, uint8_t *packet, size_t length,
                                     int timeout_ms) {
  /* One-time chip-state dump at the FIRST station TX, to compare the live
   * TX-path state against the kernel's known-good values (CR=0x06ff,
   * TXPAUSE=0x00). The usbmon "final write" can mislead; this reads the chip. */
  static bool sta_first_dump = true;
  if (sta_first_dump) {
    sta_first_dump = false;
    try {
      uint16_t cr      = rtw_read16(0x0100);
      uint8_t  txpause = rtw_read8(0x0522);
      uint32_t fwhw    = rtw_read32(0x0420);
      uint16_t trxdma  = rtw_read16(0x010C);
      uint8_t  ant     = rtw_read8(0x0808);   /* RX/TX antenna sel (IQK zeroes it) */
      uint32_t bbcca   = rtw_read32(0x0838);  /* CCA / OFDM-TX path (IQK sets 0xc) */
      uint8_t  cckrx   = rtw_read8(0x0a07);   /* CCK RX path (IQK sets 0xf) */
      uint32_t rrsr    = rtw_read32(0x0604);
      uint32_t bbtxA   = rtw_read32(0x0c04);  /* path-A TX path enable (BB) */
      uint32_t bbtxB   = rtw_read32(0x0e04);  /* path-B TX path enable (BB) */
      _logger->info("STA-pre-TX/1 CR=0x{:04x} TXPAUSE=0x{:02x}", cr, txpause);
      _logger->info("STA-pre-TX/2 FWHW_TXQ=0x{:08x} TRXDMA=0x{:04x}", fwhw, trxdma);
      _logger->info("STA-pre-TX/3 ANT808=0x{:02x} CCA838=0x{:08x}", ant, bbcca);
      _logger->info("STA-pre-TX/4 CCKRXa07=0x{:02x} RRSR=0x{:08x}", cckrx, rrsr);
      _logger->info("STA-pre-TX/5 BBtxA_c04=0x{:08x} BBtxB_e04=0x{:08x}", bbtxA, bbtxB);
      /* RFE (RF front-end / antenna TR switch) in BB Page C. Expect 0x00508242
       * (the 8812 BB-table value) once the post-IQK restore is in. 0 = the IQK
       * zeroed it = the on-air-silence bug. Save/restore the page so the TX is
       * unaffected. */
      uint32_t pc  = rtw_read32(0x082c);
      rtw_write32(0x082c, pc & ~0x80000000u);
      uint32_t rfeA = rtw_read32(0x0cb8);
      uint32_t rfeB = rtw_read32(0x0eb8);
      rtw_write32(0x082c, pc);
      _logger->info("STA-pre-TX/6 RFE_cb8/eb8(PageC)=0x{:08x}/0x{:08x}", rfeA, rfeB);
    } catch (...) {}
  }
  /* No libusb_clear_halt here. rtw88_8814au's usbmon shows the first bulk
   * OUT is preceded by 0 CLEAR_FEATUREs; later CLEAR_FEATUREs happen during
   * normal TX-queue operation, not the per-send hot path. Resetting the
   * data toggle bit corrupts the chip's state machine. */
  _txWaiting->store(true);                    // make the RX loop yield the bus
  std::unique_lock<std::mutex> lk(*_busMtx);  // exclusive bus for this TX
  int actual = 0;
  int rc = libusb_bulk_transfer(_dev_handle, ep, packet,
                                static_cast<int>(length), &actual, timeout_ms);
  _txWaiting->store(false);
  if (rc != LIBUSB_SUCCESS) {
    _logger->error("bulk_send EP {} FAIL rc={} got {}/{}", (int)ep, rc,
                   actual, (int)length);
    return rc;
  }
  _logger->info("bulk_send EP {} OK {} bytes", (int)ep, actual);
  /* DECISIVE: did the frame leave the TX FIFO? Read REG_TXPKT_EMPTY (0x041A)
   * before-ish (the dump read it at sta state) and now after a settle. If the
   * mgmt/high queue empties, the chip transmitted/drained it (=> radiation/RF or
   * AP issue). If it stays non-empty, the TX DMA never fired (=> chip TX gating).
   * Also REG_TXFF_STATUS (0x0418) + the per-queue free-page. One-time only. */
  static bool sta_post_check = true;
  if (sta_post_check) {
    sta_post_check = false;
    try {
      uint16_t e0 = rtw_read16(0x041A);
      std::this_thread::sleep_for(std::chrono::milliseconds(8));
      uint16_t e1 = rtw_read16(0x041A);
      uint32_t hisr = rtw_read32(0x00b4);   /* HISR — TX-OK interrupt flags */
      _logger->info("STA-post-TX TXPKT_EMPTY 0x41a: {:#06x}->{:#06x}  HISR(0xb4)={:#010x}",
                    e0, e1, hisr);
    } catch (...) {}
  }
  return actual;
}

// ---- Kernel-style async RX (APFPV station path) ---------------------------
// Ported from the Linux 88XXau usb_read_port_complete / usb_recv_tasklet split
// (os_dep/linux/usb_ops_linux.c). The completion CALLBACK must do *minimal* work
// and resubmit the URB IMMEDIATELY, so the bulk-IN URB pool is always refilled
// and the shared libusb event loop never stalls (a stalled loop = RX gaps AND
// the async bulk-OUT TX never completes -> auth/assoc time out). The expensive
// recvbuf2recvframe parse + dispatch run on a SEPARATE worker thread (the kernel
// tasklet), NOT inline in the callback. This is the fix for "2 beacons received,
// 0 auth responses, TX status-2 timeout".
struct RtlUsbAdapter::AsyncRxState {
  Logger_t logger;
  std::function<void(const Packet &)> proc;
  std::atomic<bool> running{true};
  std::atomic<int> inflight{0};
  std::vector<libusb_transfer *> transfers;
  std::vector<std::vector<uint8_t>> buffers;
  // recv_tasklet queue: the URB callback pushes a raw recvbuf copy here and
  // resubmits; the worker pops + parses off the event-loop thread.
  std::mutex qMtx;
  std::condition_variable qCv;
  std::deque<std::vector<uint8_t>> queue;
  std::thread worker;
  std::atomic<uint64_t> rxBufs{0};        // recvbufs handed to the worker (diag)
  // While paused, the callback retires URBs WITHOUT resubmitting, so the bulk-IN
  // pipe drains and a bulk-OUT TX can go (libusb userspace serialises OUT behind
  // pending INs on both WinUSB and USB/IP — unlike the Linux kernel USB core).
  std::atomic<bool> paused{false};
  // Per-transfer ownership: true = in flight (owned by libusb), false = retired
  // (owned by us, safe to resubmit). Index-parallel to `transfers`. This is the
  // source of truth for "may I submit transfers[i]" and replaces the racy reliance
  // on the aggregate `inflight` counter (which silently drifted under double-submit).
  std::vector<std::unique_ptr<std::atomic<bool>>> submitted;
  libusb_context *ctx{nullptr};   // for actively pumping events during the drain
};

// usb_recv_tasklet equivalent: one persistent FrameParser drains the queue and
// dispatches frames. Off the libusb event thread, so a slow consumer never
// stalls URB refill / TX completion.
static void apfpv_rx_worker(RtlUsbAdapter::AsyncRxState *st) {
  FrameParser fp{st->logger};
  for (;;) {
    std::vector<uint8_t> buf;
    {
      std::unique_lock<std::mutex> lk(st->qMtx);
      st->qCv.wait(lk, [st] { return !st->queue.empty() || !st->running.load(); });
      if (!st->running.load() && st->queue.empty()) break;
      buf = std::move(st->queue.front());
      st->queue.pop_front();
    }
    try {
      auto pkts = fp.recvbuf2recvframe(std::span<uint8_t>{buf.data(), buf.size()});
      for (auto &p : pkts) st->proc(p);
    } catch (...) {}
  }
}

static void LIBUSB_CALL apfpv_async_rx_cb(libusb_transfer *xfer) {
  auto *st = static_cast<RtlUsbAdapter::AsyncRxState *>(xfer->user_data);
  if (xfer->status == LIBUSB_TRANSFER_COMPLETED && xfer->actual_length > 0) {
    // MINIMAL inline work (rtw_enqueue_recvbuf): copy the recvbuf, hand it to the
    // worker, then fall through to resubmit IMMEDIATELY. No parsing here.
    {
      std::lock_guard<std::mutex> lk(st->qMtx);
      st->queue.emplace_back(xfer->buffer, xfer->buffer + xfer->actual_length);
    }
    st->rxBufs.fetch_add(1);
    st->qCv.notify_one();
  }
  bool fatal = (xfer->status == LIBUSB_TRANSFER_CANCELLED ||
                xfer->status == LIBUSB_TRANSFER_NO_DEVICE);
  size_t idx = (size_t)-1;
  for (size_t i = 0; i < st->transfers.size(); ++i)
    if (st->transfers[i] == xfer) { idx = i; break; }
  if (st->running.load() && !st->paused.load() && !fatal &&
      libusb_submit_transfer(xfer) == 0)
    return;                       // re-queued, flag stays true, still in flight
  if (idx != (size_t)-1 && idx < st->submitted.size())
    st->submitted[idx]->store(false, std::memory_order_release);
  st->inflight.fetch_sub(1);      // retired this URB (cancelled / paused / fatal)
}

void RtlUsbAdapter::startAsyncRx(std::function<void(const Packet &)> processor,
                                 int numUrbs) {
  stopAsyncRx();
  auto st = std::make_shared<AsyncRxState>();
  st->logger = _logger;
  st->proc = std::move(processor);
  st->running.store(true);
  st->worker = std::thread(apfpv_rx_worker, st.get());   // start the recv_tasklet
  // Native USB: 0 = no timeout (kernel model). Over WSL USB/IP an always-pending
  // IN URB blocks the OUT URB, so DEVOURER_RX_URB_TO (ms) lets the IN URBs cycle.
  unsigned urbTo = 0;
  if (const char *e = std::getenv("DEVOURER_RX_URB_TO")) urbTo = (unsigned)std::atoi(e);
  st->ctx = *_usbCtx;                       // capture for the event-pump drain
  st->buffers.resize(numUrbs);
  st->transfers.reserve(numUrbs);
  st->submitted.reserve(numUrbs);
  for (int i = 0; i < numUrbs; ++i) {
    st->buffers[i].resize(16 * 1024);
    libusb_transfer *t = libusb_alloc_transfer(0);
    libusb_fill_bulk_transfer(t, _dev_handle, _bulk_in_ep, st->buffers[i].data(),
                              (int)st->buffers[i].size(), apfpv_async_rx_cb,
                              st.get(), urbTo);
    st->transfers.push_back(t);
    st->submitted.push_back(std::make_unique<std::atomic<bool>>(false));
    if (libusb_submit_transfer(t) == 0) {
      st->submitted[i]->store(true, std::memory_order_release);
      st->inflight.fetch_add(1);
    }
  }
  _asyncRx = st;
  _logger->info("async RX: {} URBs in flight (+recv worker)", st->inflight.load());
}

void RtlUsbAdapter::stopAsyncRx() {
  auto st = _asyncRx;
  if (!st) return;
  st->running.store(false);
  for (auto *t : st->transfers) libusb_cancel_transfer(t);
  for (int i = 0; i < 200 && st->inflight.load() > 0; ++i)
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  st->qCv.notify_all();                       // wake the worker so it can exit
  if (st->worker.joinable()) st->worker.join();
  for (auto *t : st->transfers) libusb_free_transfer(t);
  _asyncRx.reset();
}

// Drain the bulk-IN URB pool so a bulk-OUT TX can go (see AsyncRxState::paused).
// Cancels the in-flight RX URBs and waits for them to retire. The recv worker +
// queue are untouched, so buffers already received are still parsed.
void RtlUsbAdapter::pauseAsyncRx() {
  auto st = _asyncRx;
  if (!st) return;
  // Tell the external event thread to YIELD: otherwise it contends the libusb event
  // lock with our drain pump below + the cal's synchronous control reads, leaving an IN
  // pending and corrupting/serializing those reads (the daemon-vs-direct-call race).
  if (_rxQuiesce) _rxQuiesce->store(true, std::memory_order_release);
  st->paused.store(true);
  for (auto *t : st->transfers) libusb_cancel_transfer(t);
  // Actively pump events so the CANCELLED completions are reaped HERE — don't rely
  // on the dedicated event thread being scheduled in time (that race leaves an IN
  // pending and the OUT serializes behind it -> status=2 timeout). Bounded; falls
  // back to sleeping only if no ctx was wired.
  auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(150);
  while (st->inflight.load() > 0 &&
         std::chrono::steady_clock::now() < deadline) {
    if (st->ctx) { struct timeval tv { 0, 1000 }; libusb_handle_events_timeout(st->ctx, &tv); }
    else std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

// Re-arm the bulk-IN URB pool after a TX. Resubmits every URB in the pool.
void RtlUsbAdapter::resumeAsyncRx() {
  auto st = _asyncRx;
  if (!st) return;
  st->paused.store(false);
  for (size_t i = 0; i < st->transfers.size(); ++i) {
    bool expected = false;
    if (!st->submitted[i]->compare_exchange_strong(
            expected, true, std::memory_order_acq_rel))
      continue;                                  // still in flight — never double-submit
    if (libusb_submit_transfer(st->transfers[i]) == 0)
      st->inflight.fetch_add(1);
    else
      st->submitted[i]->store(false, std::memory_order_release);
  }
  if (_rxQuiesce) _rxQuiesce->store(false, std::memory_order_release);  // event thread resumes
}

// Station TX that coexists with the kernel-tasklet async RX. libusb userspace
// can't push a bulk-OUT while bulk-IN URBs are pending (WinUSB + USB/IP both
// serialise OUT behind INs), so: drain the RX pool, do the proven sync bulk-OUT,
// then immediately re-arm RX (fast, so the AP's reply that follows is caught).
bool RtlUsbAdapter::sendStationFrameSync(uint8_t *data, size_t len) {
  // Recover a possibly-halted/stalled TX EP before EACH station TX. A NAK'd or
  // failed bulk-OUT can leave the EP stalled so every subsequent OUT times out
  // (status=2) — the FailTx wedge. send_packet only clears it on the very first
  // send. clear_halt resets the data toggle on BOTH host + device so it stays in
  // sync (and the prior station TX has already completed before we get here).
  // *** clear_halt is OFF by default — it was the root cause of on-air silence. ***
  // It was added to recover the WSL/vhci "FailTx wedge" (status=2 bulk-OUT), but
  // clear_halt resets the EP/data-toggle mid-path and DISRUPTS the real transmission:
  // the MAC drains the FIFO (TXPKT_EMPTY=0xfff) yet the frame never goes on-air. PROVEN
  // on native Windows against the OnePlus AP's own hostapd RX log — WITH clear_halt the
  // auth never reaches the AP (0 frames over 22s while foreign frames were logged);
  // WITHOUT it the connect reaches Handshaking (auth+assoc OK). The beacon injector never
  // clear_halt'd and always radiated (-52 dBm). Opt-in via DEVOURER_TX_HALT_CLR for the
  // WSL/vhci wedge case only.
  if (std::getenv("DEVOURER_TX_HALT_CLR")) {
    uint8_t ep = 0x02;
    if (const char *e = std::getenv("DEVOURER_TX_EP")) ep = (uint8_t)std::strtoul(e, nullptr, 0);
    else if (!_bulk_out_eps.empty()) ep = _bulk_out_eps[0];
    libusb_clear_halt(_dev_handle, ep);
  }
  if (!std::getenv("DEVOURER_TX_USE_PAUSE")) {
    // DEFAULT (validated): concurrent IN/OUT exactly like the kernel USB core — do NOT
    // cancel the RX URBs, so the AP's auth/assoc reply (which arrives ~1ms after our TX)
    // is caught on the still-live RX. The per-TX clear_halt above is what keeps the OUT
    // from wedging (status=2 timeout) behind the pending INs — without it this path
    // wedged, which is why RX was historically paused. With both together the devourer
    // reaches Associating[PASS] on WSL-vhci (the worst-case transport). The legacy
    // drain-RX-then-TX path is still available via DEVOURER_TX_USE_PAUSE.
    bool ok = send_packet(data, len);
    // ACK-DRIVEN (kernel-style) instead of a blind sleep: watch the chip confirm the frame
    // left the TX FIFO via REG_TXPKT_EMPTY (0x041A). Logs the drain so a SILENT run is
    // diagnosable — FIFO never empties => chip gated the TX (no radiation, a concurrency/
    // chip problem) vs FIFO drains => frame went out (an RF/AP problem). Bounded ~40ms.
    if (!std::getenv("DEVOURER_TX_BLIND")) {
      uint16_t e0 = 0, e = 0;
      try { e0 = rtw_read16(0x041A); } catch (...) {}
      auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(40);
      int settled = 0;
      e = e0;
      do {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
        uint16_t cur = e;
        try { cur = rtw_read16(0x041A); } catch (...) { break; }
        if (cur == e) { if (++settled >= 3) break; } else { settled = 0; e = cur; }
      } while (std::chrono::steady_clock::now() < deadline);
      _logger->info("STA-TX ack: TXPKT_EMPTY 0x41a {:#06x}->settled {:#06x}", e0, e);
      return ok;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    return ok;
  }
  bool hadRx = (_asyncRx != nullptr) && !_asyncRx->paused.load();
  if (hadRx) pauseAsyncRx();
  bool ok;
  if (std::getenv("DEVOURER_STA_SYNC_TX")) {
    int rc = bulk_send_sync_ep(0x02, data, len, 200);
    ok = (rc == (int)len);        // bulk_send_sync_ep returns bytes sent, or <0
  } else {
    // ASYNC submit path — the SAME path the beacon injector uses. It sets
    // LIBUSB_TRANSFER_ADD_ZERO_PACKET and does NOT wedge after the first TX the way
    // the sync libusb_bulk_transfer does (which returns -7/TIMEOUT on every send
    // after the first). Wait briefly for the OUT + the MAC TX/retry to complete
    // before re-arming the RX so the AP's reply is still caught.
    ok = send_packet(data, len);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  if (hadRx) resumeAsyncRx();
  return ok;
}

void RtlUsbAdapter::phy_set_bb_reg(uint16_t regAddr, uint32_t bitMask,
                                   uint32_t data) {
  PHY_SetBBReg8812(regAddr, bitMask, data);
}

void RtlUsbAdapter::PHY_SetBBReg8812(uint16_t regAddr, uint32_t bitMask,
                                     uint32_t dataOriginal) {
  uint32_t data = dataOriginal;
  if (bitMask != bMaskDWord) {
    /* if not "double word" write */
    auto OriginalValue = rtw_read32(regAddr);
    auto BitShift = PHY_CalculateBitShift(bitMask);
    data = ((OriginalValue) & (~bitMask)) |
           (((dataOriginal << (int)BitShift)) & bitMask);
  }

  rtw_write32(regAddr, data);

  /* RTW_INFO("BBW MASK=0x%x Addr[0x%x]=0x%x\n", BitMask, RegAddr, Data); */
}
