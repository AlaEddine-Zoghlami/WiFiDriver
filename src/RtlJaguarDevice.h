#ifndef RTL_JAGUAR_DEVICE_H
#define RTL_JAGUAR_DEVICE_H

#include <functional>
#include <iostream>
#include <iomanip>

#include "logger.h"
#include "HalModule.h"
#include "SelectedChannel.h"
#include "EepromManager.h"
#include "RadioManagementModule.h"
#include "FrameParser.h"

extern "C"
{
#include "ieee80211_radiotap.h"
}

using Action_ParsedRadioPacket = std::function<void(const Packet&)>;

/* RtlJaguarDevice is the orchestrator for the Realtek "Jaguar" 802.11ac family
 * — RTL8812AU (2T2R), RTL8811AU (1T1R cut), and RTL8814AU (4T4R RF / 3-SS
 * baseband). The chip is identified at construction time via SYS_CFG bits and
 * USB PID; this class drives bring-up, RX, and TX for whichever member of the
 * family is present. */
class RtlJaguarDevice {
  std::shared_ptr<EepromManager> _eepromManager;
  std::shared_ptr<RadioManagementModule> _radioManagement;
  SelectedChannel _channel;
  RtlUsbAdapter _device;
  HalModule _halModule;
  Logger_t _logger;
  uint8_t debug;
  Action_ParsedRadioPacket _packetProcessor = nullptr;

public:
  RtlJaguarDevice(RtlUsbAdapter device, Logger_t logger);
  void Init(Action_ParsedRadioPacket packetProcessor, SelectedChannel channel);
  // Accessors for the APFPV station orchestrator (it drives arm/assoc/TX on the
  // same adapter + radio this device owns).
  RtlUsbAdapter& adapter() { return _device; }
  RadioManagementModule& radioManager() { return *_radioManagement; }
  void SetMonitorChannel(SelectedChannel channel);
  void InitWrite(SelectedChannel channel);
  // Kernel-style async RX: bring the PHY up in monitor mode, then keep N bulk-IN
  // URBs in flight delivering to `processor` (driven by the caller's
  // libusb_handle_events loop). Returns immediately — NO blocking read loop, so
  // a concurrent async TX can run. Used by the APFPV station path.
  void StartMonitorAsyncRx(Action_ParsedRadioPacket processor, SelectedChannel channel);
  void StopAsyncRx();
  void SetTxPower(uint8_t power);
  uint8_t GetTxPower();
  bool send_packet(const uint8_t* packet, size_t length);
  SelectedChannel GetSelectedChannel();
  bool should_stop = false;

private:
  void StartWithMonitorMode(SelectedChannel selectedChannel);
  bool NetDevOpen(SelectedChannel selectedChannel);
};

/* Backwards-compatibility alias. External callers using the old name still
 * compile but get a deprecation warning. Remove after one release cycle. */
using Rtl8812aDevice [[deprecated("renamed to RtlJaguarDevice")]] =
    RtlJaguarDevice;

#endif /* RTL_JAGUAR_DEVICE_H */
