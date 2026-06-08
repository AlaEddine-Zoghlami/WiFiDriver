#ifndef RTLUSBADAPTER_H
#define RTLUSBADAPTER_H

#include <iostream>

#include <libusb.h>
#include <thread>
#include <vector>
#include <mutex>
#include <atomic>
#include <memory>
#include <functional>

#include "FrameParser.h"
#include "drv_types.h"
#include "hal_com_reg.h"
#include "logger.h"

#define rtw_read8 rtw_read<uint8_t>
#define rtw_read16 rtw_read<uint16_t>
#define rtw_read32 rtw_read<uint32_t>

#define rtw_write8 rtw_write<uint8_t>
#define rtw_write16 rtw_write<uint16_t>
#define rtw_write32 rtw_write<uint32_t>

#define REALTEK_USB_VENQT_READ 0xC0
#define REALTEK_USB_VENQT_WRITE 0x40
#define USB_TIMEOUT 500

enum TxSele {
  TX_SELE_HQ = 1 << (0), /* High Queue */
  TX_SELE_LQ = 1 << (1), /* Low Queue */
  TX_SELE_NQ = 1 << (2), /* Normal Queue */
  TX_SELE_EQ = 1 << (3), /* Extern Queue */
};

class RtlUsbAdapter {
  libusb_device_handle *_dev_handle;
  Logger_t _logger;

  enum libusb_speed usbSpeed;
  uint8_t numOutPipes = 0;
  /* Bulk-IN endpoint address used by infinite_read(). 8812AU / 8814AU expose
   * IN endpoint at 0x81; 8821AU has a different descriptor (no 0x81), so we
   * pick this up from the interface descriptor at InitDvObj time instead of
   * hardcoding. Default 0x81 keeps existing behaviour for 88[12,14]AU when
   * the descriptor walk doesn't override. */
  uint8_t _bulk_in_ep = 0x81;
  /* Bulk-OUT endpoint addresses, in descriptor order. 8812AU exposes 4 OUT
   * EPs at 0x02/0x03/0x04/0x05 (HQ/NQ/LQ/EQ); 8821AU exposes 0x05/0x06/0x08/
   * 0x09. send_packet picks index 0 (HQ-equivalent) by default; DEVOURER_TX_EP
   * env override still wins for diagnostic bisection. */
  std::vector<uint8_t> _bulk_out_eps;

  uint16_t _idVendor = 0;
  uint16_t _idProduct = 0;
  uint8_t  _lastH2CBox = 0;   // round-robins 0..3 across H2C mailboxes

public:
  // Serialises bulk RX (infinite_read) and bulk TX (bulk_send_sync) so the two
  // never submit concurrent URBs on the same libusb context — concurrent sync
  // RX + TX race the URB queue and the TX times out (station-mode TX silence).
  // _txWaiting lets the RX loop yield its turn the instant a TX needs the bus.
  // shared_ptr: RtlUsbAdapter is COPIED by value (RtlJaguarDevice stores a copy)
  // but all copies wrap the SAME libusb handle, so they must share one mutex.
  std::shared_ptr<std::mutex> _busMtx = std::make_shared<std::mutex>();
  std::shared_ptr<std::atomic<bool>> _txWaiting =
      std::make_shared<std::atomic<bool>>(false);
  struct AsyncRxState;                       // defined in the .cpp
  std::shared_ptr<AsyncRxState> _asyncRx;   // async RX URB pool (shared across copies)
  // libusb context for the event-pump drain in pauseAsyncRx. shared_ptr so it
  // survives RtlUsbAdapter value-copies (same pattern as _busMtx / _asyncRx).
  std::shared_ptr<libusb_context*> _usbCtx = std::make_shared<libusb_context*>(nullptr);
  void setUsbContext(libusb_context *c) { *_usbCtx = c; }
  // Set true while RX is paused/draining so the EXTERNAL libusb event thread YIELDS
  // instead of contending the event lock with pauseAsyncRx's own drain pump and the
  // cal's synchronous control reads (the daemon-vs-direct-call serialization fix).
  std::shared_ptr<std::atomic<bool>> _rxQuiesce;
  void setQuiesceFlag(std::shared_ptr<std::atomic<bool>> q) { _rxQuiesce = std::move(q); }
private:

public:
  RtlUsbAdapter(libusb_device_handle *dev_handle, Logger_t logger);

  uint16_t idVendor() const { return _idVendor; }
  uint16_t idProduct() const { return _idProduct; }

  bool AutoloadFailFlag = false;
  bool EepromOrEfuse = false;
  uint8_t OutEpQueueSel;
  uint8_t OutEpNumber;
  uint8_t rxagg_usb_size;
  uint8_t rxagg_usb_timeout;
  bool send_packet(uint8_t* packet, size_t length);
  /* Synchronous bulk-OUT transfer that blocks until completion or timeout.
   * Returns the number of bytes actually transferred, or negative on error. */
  int bulk_send_sync(uint8_t *packet, size_t length, int timeout_ms);
  void bulk_clear_halt(uint8_t ep) { libusb_clear_halt(_dev_handle, ep); }
  int bulk_send_sync_ep(uint8_t ep, uint8_t *packet, size_t length,
                        int timeout_ms);
  std::vector<Packet> infinite_read();
  uint8_t efuse_OneByteRead(uint16_t addr, uint8_t *data);
  void phy_set_bb_reg(uint16_t regAddr, uint32_t bitMask, uint32_t data);

  template <typename T> T rtw_read(uint16_t reg_num) {
    T data = 0;
    if (libusb_control_transfer(_dev_handle, REALTEK_USB_VENQT_READ, 5, reg_num,
                                0, (uint8_t *)&data, sizeof(T),
                                USB_TIMEOUT) == sizeof(T)) {
      return data;
    }

    _logger->error("rtw_read({:04x}), sizeof(T) = {}", reg_num, sizeof(T));
    throw std::ios_base::failure("rtw_read");
    return 0;
  }

  template <typename T> bool rtw_write(uint16_t reg_num, T value) {
    if (libusb_control_transfer(_dev_handle, REALTEK_USB_VENQT_WRITE, 5,
                                reg_num, 0, (uint8_t *)&value, sizeof(T),
                                USB_TIMEOUT) == sizeof(T)) {
      return true;
    }
    return false;
  }

  bool WriteBytes(uint16_t reg_num, uint8_t *ptr, size_t size);

  // Host-to-Card firmware command (8812 mailbox: REG_HMEBOX_0 / EXT_0, 4 boxes).
  // Needed to send the MEDIA_STATUS_RPT that makes the HW MAC act as a connected
  // station (auto-ACK auth/assoc). Returns false if the write failed.
  bool fillH2CCmd(uint8_t elementID, uint32_t cmdLen, const uint8_t *cmdBuffer);

  // ---- Kernel-style async RX (APFPV station path) -------------------------
  // Keeps `numUrbs` bulk-IN URBs permanently in flight (the 88XXau model),
  // delivering parsed Packets to `processor` from a libusb_handle_events loop.
  // This replaces the blocking sync infinite_read() so a concurrent async TX
  // (send_packet) can complete — the two no longer fight over the event handler.
  // The caller MUST run libusb_handle_events on the device's context.
  struct AsyncRxState;
  void startAsyncRx(std::function<void(const Packet &)> processor, int numUrbs = 8);
  void stopAsyncRx();
  // Coexist TX with the async RX pool: drain RX URBs, sync-TX, re-arm RX.
  void pauseAsyncRx();
  void resumeAsyncRx();
  bool sendStationFrameSync(uint8_t *data, size_t len);

  void rtl8812au_hw_reset();
  void _8051Reset8812();
  void ReadEFuseByte(uint16_t _offset, uint8_t *pbuf);

private:
  void InitDvObj();
  const char *strUsbSpeed();
  void GetChipOutEP8812();
  void PHY_SetBBReg8812(uint16_t regAddr, uint32_t bitMask,
                        uint32_t dataOriginal);
};

#endif /* RTLUSBADAPTER_H */
