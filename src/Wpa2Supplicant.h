#pragma once
#include <cstdint>
#include <vector>
#include <array>
#include <string>
#include <functional>
#include "Wpa2Crypto.h"
namespace apfpv {
using Mac = std::array<uint8_t,6>;
class Wpa2Supplicant {
public:
    using SendFn = std::function<bool(const std::vector<uint8_t>&)>;
    Wpa2Supplicant(Crypto c, SendFn send);
    void begin(const std::string& passphrase, const std::string& ssid, const Mac& self, const Mac& bssid);
    // Fast path: skip the (slow ~seconds) PBKDF2 by injecting a pre-computed PMK. The PMK
    // depends ONLY on passphrase+SSID, so it can be cached across connects. CRITICAL: the
    // AP only advertises M1 for ~4s (4 retries); if begin() does PBKDF2 inline the RX
    // doesn't switch to the EAPOL/streaming phase until after the AP gives up -> M1 missed.
    void beginCached(const std::array<uint8_t,32>& pmk, const Mac& self, const Mac& bssid);
    const std::array<uint8_t,32>& pmk() const { return _pmk; }
    bool onEapolKey(const uint8_t* body, size_t len);
    bool ready() const;
    void setPmf(int p) { _pmf = p; }                 // 802.11w: 0=off 1=capable 2=required
    bool pmfActive() const { return _pmf > 0 && _state == State::Done; }
    // Verify a protected broadcast/multicast mgmt frame (Deauth/Disassoc carrying an MME)
    // with BIP-CMAC-128 against the installed IGTK. false => forged/unverifiable -> ignore it.
    bool verifyProtectedMgmt(const uint8_t* frame, size_t len) const;
    bool decryptData(const uint8_t* frame, size_t len, std::vector<uint8_t>& plain);
    // Build an ENCRYPTED 802.11 data frame (CCMP) carrying an IP/UDP payload.
    // Used to TX DHCP (and any station uplink) after the 4-way handshake.
    // 'ipPayload' is a complete IPv4 packet (IP+UDP+BOOTP). Returns the full
    // 802.11 frame ready for send_packet (caller prepends the TX descriptor).
    std::vector<uint8_t> buildEncryptedData(const uint8_t* ipPayload, size_t len, uint16_t ethertype = 0x0800);
    const std::array<uint8_t,16>& tk() const { return _tk; }
private:
    enum class State { Idle, WaitMsg1, WaitMsg3, Done };
    void derivePtk(const uint8_t* aNonce);
    std::vector<uint8_t> buildMsg2();
    std::vector<uint8_t> buildMsg4();
    std::vector<uint8_t> buildGroupMsg2();              // group-rekey ACK (Key Type=Group)
    bool installGtkFromKeyData(const uint8_t* body, size_t len);  // unwrap+install GTK (M3 & rekey)
    Crypto _c; SendFn _send;
    Mac _self{}, _bssid{};
    std::array<uint8_t,32> _pmk{}; std::array<uint8_t,16> _kck{}, _kek{}, _tk{}, _gtk{}, _gtkPrev{};
    std::array<uint8_t,32> _aNonce{}, _sNonce{};
    // Two GTK slots indexed by CCMP KeyID so frames in-flight on the OLD key still decrypt
    // across a group rekey (else the ~1s around a rekey loses broadcast/multicast).
    uint8_t _gtkKeyId = 0xff, _gtkPrevId = 0xff;       // 0xff = unset
    int _pmf = 0;                                      // 802.11w mode (RSN caps in M2)
    std::array<uint8_t,16> _igtk{}; uint16_t _igtkKeyId = 0; bool _igtkSet = false;  // BIP key
    // CCMP RX replay windows (per key): a frame's 48-bit PN must strictly increase.
    uint64_t _rxPnPair = 0; uint64_t _rxPnGtk[4] = {0,0,0,0};
    State _state = State::Idle; uint64_t _replay = 0; uint64_t _txPn = 1; uint8_t _replayCtr[8] = {0};
    std::vector<uint8_t> _lastKeyFrame;
};
}
