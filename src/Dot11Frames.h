#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <array>
namespace apfpv {
using Mac = std::array<uint8_t,6>;
std::vector<uint8_t> BuildAuthOpenSeq1(const Mac& self, const Mac& bssid);
// Open (no-privacy) beacon for the EIRP-calibration "VRX beacon" mode: lets a
// phone Wi-Fi scan see the dongle as an AP so its EIRP can be measured.
std::vector<uint8_t> BuildBeacon(const Mac& self, const std::string& ssid, uint8_t channel,
                                 bool wpa2 = false);
// AP-side mgmt responses + AP EAPOL-Key (from-DS) for the WPA2 Authenticator.
std::vector<uint8_t> BuildAuthResp(const Mac& ap, const Mac& sta);
std::vector<uint8_t> BuildAssocResp(const Mac& ap, const Mac& sta, uint16_t aid);
std::vector<uint8_t> BuildProbeResp(const Mac& ap, const Mac& sta, const std::string& ssid,
                                    uint8_t channel, bool wpa2 = false);
std::vector<uint8_t> BuildEapolKeyFromAp(const Mac& ap, const Mac& sta,
                                         const std::vector<uint8_t>& keyBody);
// operBw is the width we will actually operate at (0=20, 1=40, 2=80). It only affects the
// Operating Mode Notification; HT/VHT capability IEs always advertise the chip's full ability
// (40 MHz, SGI-20/40, HT MCS0-15, VHT 2SS) so the AP's rate control is free to pick 2SS at any
// width. Defaults to 80 MHz to preserve the historical behaviour of existing call sites.
std::vector<uint8_t> BuildAssocRequest(const Mac& self, const Mac& bssid, const std::string& ssid,
                                       uint16_t rsnCaps = 0, uint8_t operBw = 2);
// Negotiated variant: RSN IE reflects the cipher chosen from the AP's beacon.
// rsnCaps carries the RSN capabilities (802.11w MFPC bit7 / MFPR bit6); 0 = no PMF.
std::vector<uint8_t> BuildAssocRequest(const Mac& self, const Mac& bssid, const std::string& ssid,
                                       uint32_t pairwiseCipher, uint32_t groupCipher,
                                       uint16_t rsnCaps = 0, uint8_t operBw = 2);
std::vector<uint8_t> BuildEapolKey(const Mac& self, const Mac& bssid, const std::vector<uint8_t>& keyBody);
}
