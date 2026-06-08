// ============================================================================
//  StationMode.cpp  —  station-mode arming + ACK-survival probe (impl)
//  Declarations in StationMode.h. The auto-ACK arming sequence is ported from
//  the Linux driver hw_var_set_opmode STATION path (see docs/ARMING_SEQUENCE.md):
//      MACID -> MSR=STATION(0x02) -> BSSID -> RCR|=RCR_CBSSID_DATA(BIT6)
//  All register symbols confirmed in devourer hal/hal_com_reg.h.
// ============================================================================
#include "StationMode.h"
#include "Dot11Frames.h"
#include "StationTxDesc.h"
#include "hal_com_reg.h"

#include <cstring>
#include <chrono>
#include <thread>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include "RadioManagementModule.h"
#ifdef __ANDROID__
#include <android/log.h>
#define SMLOG(...) __android_log_print(ANDROID_LOG_INFO, "apfpv-arm", __VA_ARGS__)
#else
#define SMLOG(...) ((void)0)
#endif

namespace apfpv {

static constexpr uint8_t HW_STATE_STATION = 0x02;   // MSR_INFRA
static constexpr int     TXDESC_8812      = 40;

StationMode::StationMode(RtlUsbAdapter& dev, RadioManagementModule& rm, SendFrameFn send)
    : _dev(dev), _rm(rm), _send(std::move(send)) {}

void StationMode::arm(const MacAddr& self, const MacAddr& bssid) {
    // (0) **SEQUENCE FIX — IQK on the OPERATING channel.** Faithful to the kernel
    // join order (rtw_mlme_ext.c join_cmd_hdl): HW_VAR_DO_IQK(TRUE) -> set_channel_
    // bwmode(final channel) so the IQK runs on the channel we will actually use,
    // -> MSR=STATION -> issue_auth. The devourer only ran the IQK during init on
    // the init/scan channel; the IQK output (per-channel TX/RX IQ calibration) is
    // then WRONG for the AP's channel, so the auth radiates mis-calibrated and the
    // AP can't decode it. Re-arm + re-run the channel-set here, on the channel the
    // scan settled on, immediately before auth. (TXPAUSE that the IQK/LCK leave is
    // cleared by step (4c) below, which runs after this.)
    if (!std::getenv("DEVOURER_SKIP_JOIN_IQK")) {
        // The async RX is drained by the caller (runProbe) for the ENTIRE arm, so the
        // IQK/LCK cal AND the MAC/MSR/RCR/BSSID writes below all run sequentially with
        // the device quiet — like the kernel. The OLD code paused RX only around the IQK
        // here and RESUMED mid-arm, so the RX-filter writes that follow still raced the
        // RX daemon -> corrupted filter -> auth-response dropped. Whole-arm serialization
        // measured 3/5 vs 1/5 (DEVOURER_NO_PAUSE_CAL disables the runProbe-level pause).
        _rm.ArmIQKOnNextChannelSet();
        _rm.set_channel_bwmode(_rm.current_channel(), 0, CHANNEL_WIDTH_20);
    }
    // (1) own MAC -> REG_MACID
    for (int i = 0; i < 4; ++i) _dev.rtw_write8(REG_MACID + i, self.b[i]);
    _dev.rtw_write16(REG_MACID + 4, (uint16_t)(self.b[4] | (self.b[5] << 8)));
    // (2) MSR -> STATION before auth. Faithful to the kernel's start_clnt_join,
    // which calls Set_MSR(WIFI_FW_STATION_STATE)=0x02 BEFORE start_clnt_auth/
    // issue_auth (rtw_mlme_ext.c). With MSR=STATION the AP's BSSID is the chip's
    // own network, so the HW MAC filters/auto-ACKs the AP during the auth/assoc
    // handshake. (The earlier "kernel auths in NO_LINK" theory was wrong — the
    // kernel source shows STATION pre-auth.) DEVOURER_AUTH_NOLINK forces the old
    // NO_LINK behaviour for A/B bisection.
    if (!std::getenv("DEVOURER_SKIP_MSR")) {
        uint8_t netType = std::getenv("DEVOURER_AUTH_NOLINK") ? 0x00 : HW_STATE_STATION;
        uint8_t msr = (uint8_t)((_dev.rtw_read8(MSR) & 0x0C) | netType);
        _dev.rtw_write8(MSR, msr);
    }
    // (3) AP BSSID -> REG_BSSID
    for (int i = 0; i < 4; ++i) _dev.rtw_write8(REG_BSSID + i, bssid.b[i]);
    _dev.rtw_write16(REG_BSSID + 4, (uint16_t)(bssid.b[4] | (bssid.b[5] << 8)));
    // (4) RCR: station receive config. CRITICAL FIX (usbmon diff vs kernel 88XXau):
    // the previous value (0x000000ce) omitted RCR_AMF, so the HW MAC dropped EVERY
    // management frame — the AP's auth/assoc RESPONSES never reached the driver
    // (only beacons slipped through via CBSSID_BCN). It also dropped the
    // APP_PHYST/APPFCS bits that define the RX buffer layout the FrameParser
    // expects (same as monitor mode), so the few frames that did arrive misparsed.
    // This now matches the kernel station RCR exactly (0xf40060ce) and the
    // devourer's own HalModule init RCR:
    //   RCR_AMF          accept management frames (auth/assoc/deauth responses)
    //   RCR_APP_PHYST    PHY status prepended -> parser/RSSI (monitor-mode layout)
    //   RCR_APPFCS       FCS appended         -> parser frame length
    //   FORCEACK         HW auto-ACKs unicast addressed to us (AP keeps the link)
    if (!std::getenv("DEVOURER_SKIP_RCR")) {
        // RCR_ADF (accept DATA frames) is ESSENTIAL: the WPA 4-way handshake
        // (EAPOL-Key M1..M4) rides in DATA frames, not management. Without it the HW
        // MAC drops EAPOL M1 -> onEapolKey is never called -> the 4-way times out ->
        // FailAuth. The kernel's 8812a RCR (rtl8812a_hal_init.c:4163) sets RCR_ADF;
        // RCR_ACF (control) matches its connect-mode RCR. This was THE 4-way bug.
        uint32_t rcr = RCR_APM | RCR_AM | RCR_AB | RCR_ADF | RCR_ACF |
                       RCR_CBSSID_DATA | RCR_CBSSID_BCN |
                       RCR_APP_ICV | RCR_AMF | RCR_HTC_LOC_CTRL | RCR_APP_MIC |
                       RCR_APP_PHYST_RXFF | RCR_APPFCS | FORCEACK;
        _dev.rtw_write32(REG_RCR, rcr);
    }
    // (4a) Enable HW TSF update for the STA. Faithful to the kernel's
    // rtw_iface_enable_tsf_update -> rtw_hal_set_tsf_update(1) at join, which clears
    // DIS_TSF_UDT (BIT4) of REG_BCN_CTRL (0x550) so the HW syncs its TSF timer to the
    // AP's beacons/probe-resp (needed for TBTT/PS keepalive — else the AP drops us
    // after assoc). The devourer's monitor init left REG_BCN_CTRL = DIS_TSF_UDT
    // (HalModule). The kernel gates this on RCR_CBSSID_BCN, which we set above.
    // DEVOURER_SKIP_TSF disables for A/B.
    if (!std::getenv("DEVOURER_SKIP_TSF")) {
        _dev.rtw_write8(0x0550, (uint8_t)(_dev.rtw_read8(0x0550) & ~0x10));
    }
    // (4b) Join-time MAC timing the kernel 88XXau re-tunes on association but the
    // devourer's init left at monitor/default values (usbmon diff). Most important:
    // our VO/mgmt EDCA had CWmax=1023 (ECWmax 0xa) vs the kernel's 7 (0x3) — a huge
    // random backoff before every management TX. Port the kernel's exact values so
    // the auth/assoc TX is scheduled like the kernel's. Env-gated for A/B.
    if (!std::getenv("DEVOURER_SKIP_EDCA")) {
        _dev.rtw_write32(0x0500, 0x002f3222);   // REG_EDCA_VO_PARAM (mgmt/voice)
        _dev.rtw_write32(0x0504, 0x005e4322);   // REG_EDCA_VI_PARAM
        _dev.rtw_write32(0x0508, 0x005ea42b);   // REG_EDCA_BE_PARAM
        _dev.rtw_write32(0x050c, 0x0000a44f);   // REG_EDCA_BK_PARAM
        _dev.rtw_write8(0x0607, 0x07);          // REG_RRSR byte3 (response-rate ctrl)
    }
    // (4c) **THE TX-SILENCE FIX.** The IQK (Iqk8812a::ConfigureMac, run on every
    // channel-set) writes REG_TXPAUSE (0x522) = 0x3f to PAUSE all 6 TX queues during
    // calibration, but the devourer's IQK port NEVER restores it to 0 (the kernel's
    // _PHY_ReloadMACRegisters does). usbmon diff of the kernel's full init vs ours:
    // kernel TXPAUSE=0x00, devourer=0x3f. With all queues paused the chip ACCEPTS
    // the bulk-OUT into the TX FIFO ("70 bytes OK") but never transmits it -> the
    // auth/assoc never radiates and the AP never replies. Clear it here (and it is
    // the proper place: after the last channel-set/IQK, before the first TX).
    if (!std::getenv("DEVOURER_SKIP_TXPAUSE_CLR")) {
        _dev.rtw_write8(0x0522, 0x00);          // REG_TXPAUSE — release all TX queues
        SMLOG("TXPAUSE(0x522) cleared to 0x%02x", _dev.rtw_read8(0x0522));
    }
    // **THE TX-RADIATION FIX (RFE / RF front-end).** usbmon diff of the kernel's
    // full init vs ours: the kernel sets REG_RFE_CTRL 0xcb8/0xeb8 = 0x42825000
    // (routes the external PA + the antenna TX/RX switch for the TX path); the
    // devourer left them at 0x00000000. Result: the MAC transmits the frame
    // (TXPKT_EMPTY drains, "OK 70 bytes") but the signal never reaches the antenna
    // — the AP hears nothing — while RX keeps working through the LNA path. This
    // is the real cause of the "on-air silence". Also restore the TX-path AGC
    // 0xc1c/0xe1c to the kernel's value. Env-gated for A/B.
    if (std::getenv("DEVOURER_TRY_RFE")) {      // opt-in: a lone 0xcb8 write breaks RX;
                                                // needs the full RFE-config sequence.
        // 0xcb8 is PAGED: Page C = rA_RFE_Jaguar (RF front-end / PA+antenna TR
        // switch), Page C1 = rOFDM0_TxCoeff6 (a TX-IQK coefficient). Iqk8812a leaves
        // the BB in Page C1 and writes 0xcb8=0 there, so the RFE is never set to the
        // operational value AND a naive write here would corrupt the TX-IQK coeff.
        // Select Page C, then set RFE to the kernel's 8812 value (0x42825000) — our
        // 8814-derived PHY table wrongly used 0x00500000 and the IQK zeroed it.
        _dev.phy_set_bb_reg(0x82c, 0x80000000, 0x0);   // BB Page C (bit31=0)
        _dev.rtw_write32(0x0cb8, 0x42825000);          // rA_RFE_Jaguar
        _dev.rtw_write32(0x0eb8, 0x42825000);          // rB_RFE_Jaguar
        SMLOG("RFE set (Page C) 0xcb8/0xeb8=0x42825000");
    }
    // NOTE: the firmware "connected" H2C (MACID_CFG 0x40 / MEDIA_STATUS 0x01 /
    // RSSI 0x42) is deliberately NOT sent here. The kernel sends it only AFTER the
    // assoc response — see becomeStation(). Sending it pre-auth told the firmware
    // that MACID 0 was already a connected peer. DEVOURER_AUTH_STA reverts to the
    // old (pre-auth-H2C) behaviour for A/B.
    if (std::getenv("DEVOURER_AUTH_STA") && !std::getenv("DEVOURER_SKIP_H2C"))
        sendStationH2C(/*macid=*/0, bssid);
    _armed = true;
}

// Post-association transition: NOW the station is associated, so switch the chip
// to STATION network type and register the AP as a firmware peer (MACID/RA +
// media-status + RSSI H2C). This is the kernel's order — do it only after the
// assoc response, never before auth.
void StationMode::becomeStation(const MacAddr& bssid) {
    if (!std::getenv("DEVOURER_SKIP_MSR")) {
        uint8_t msr = (uint8_t)((_dev.rtw_read8(MSR) & 0x0C) | HW_STATE_STATION);
        _dev.rtw_write8(MSR, msr);
    }
    if (!std::getenv("DEVOURER_SKIP_H2C")) sendStationH2C(/*macid=*/0, bssid);
    SMLOG("becomeStation: MSR->STATION + connected H2C sent");
}

// Port of the Linux 88XXau station-association H2C firmware sequence, captured by
// usbmon-diffing a working wpa_supplicant association to OpenIPC against the
// devourer's arm(). The register arming above (MACID/MSR/BSSID/RCR) is NOT enough:
// the firmware must also have the AP registered as a *peer* (MACID) with a rate
// table + RSSI, or the chip's TX scheduler cannot pick a rate for it and the
// bulk-OUT TX FIFO wedges after the first frame (the "first TX OK, then
// -7/timeout" station-mode symptom). Each command is the elementID + params the
// kernel writes to the HMEBOX mailbox (primary box 0x1D0 + ext box 0x1F0).
//
// Individual commands are env-gated so each can be isolated on the native probe:
//   DEVOURER_SKIP_MACIDCFG / DEVOURER_SKIP_MEDIASTATUS / DEVOURER_SKIP_RSSI.
void StationMode::sendStationH2C(uint8_t macid, const MacAddr& bssid) {
    (void)bssid;
    // H2C_MACID_CFG (0x40): rate-adaptation config for the AP's MACID.
    //   parm[0]=macid, parm[1]=raid|sgi(bit5), parm[2]=bw|flags,
    //   parm[3..6]=rate mask (LE). 0x7fdff015 = 2.4GHz CCK+OFDM+HT MCS set.
    bool h2cRa = true;
    if (!std::getenv("DEVOURER_SKIP_MACIDCFG")) {
        uint8_t macidCfg[7] = { macid, 0xac, 0x10, 0x15, 0xf0, 0xdf, 0x7f };
        h2cRa = _dev.fillH2CCmd(0x40 /*H2C_MACID_CFG*/, 7, macidCfg);
    }
    // H2C_MEDIA_STATUS_RPT (0x01): MACID is now CONNECTED.
    //   parm[0]=0x21 (opmode connect, kernel value), parm[1]=macid, parm[2]=end.
    bool h2cMs = true;
    if (!std::getenv("DEVOURER_SKIP_MEDIASTATUS")) {
        uint8_t msrParm[3] = { 0x21, macid, macid };
        h2cMs = _dev.fillH2CCmd(0x01 /*H2C_MEDIA_STATUS_RPT*/, 3, msrParm);
    }
    // H2C_RSSI_SETTING (0x42): seed rate-adaptation RSSI for the MACID.
    //   parm[0]=macid, parm[1]=0, parm[2]=rssi(0x39 ~ good), parm[3]=0x06 stream.
    bool h2cRssi = true;
    if (!std::getenv("DEVOURER_SKIP_RSSI")) {
        // H2C_RSSI_SETTING is a 4-byte command (kernel H2C_RSSI_SETTING_LEN=4,
        // rtl8812_set_rssi_cmd sends len 4). Sending 7 wrote 3 ext-box bytes the
        // firmware doesn't expect. parm = {macid, 0, rssi(0x39~good), stream(0x06)}.
        uint8_t rssiSet[4] = { macid, 0x00, 0x39, 0x06 };
        h2cRssi = _dev.fillH2CCmd(0x42 /*H2C_RSSI_SETTING*/, 4, rssiSet);
    }
    SMLOG("station H2C: MACID_CFG=%d MEDIA_STATUS=%d RSSI=%d",
          h2cRa ? 1 : 0, h2cMs ? 1 : 0, h2cRssi ? 1 : 0);
}

// Management-frame TX rate, BAND-AWARE. Faithful to the kernel
// init_mlme_ext_priv_value (rtw_mlme_ext.c): a 5 GHz channel (ch>14) has no CCK
// PHY, so auth/assoc MUST go at OFDM-6M (DESC_RATE6M=0x04); 2.4 GHz uses the
// robust CCK-1M (DESC_RATE1M=0x00). Sending CCK-1M on 5 GHz is un-transmittable —
// the frame drains from the TX FIFO ("OK 70 bytes") but never radiates, which was
// our 5 GHz on-air silence. DEVOURER_MGMT_RATE overrides for A/B.
static uint8_t mgmtTxRate(int channel) {
    if (const char* r = std::getenv("DEVOURER_MGMT_RATE"))
        return (uint8_t)strtoul(r, nullptr, 0);
    return (channel > 14) ? 0x04 : 0x00;   // OFDM-6M (5 GHz) | CCK-1M (2.4 GHz)
}
// Kernel 88XXau auth/assoc TX descriptor uses MACID=1 + RAID=8 (usbmon diff),
// NOT MACID=0/RAID=0. MACID 0 is special on Jaguar; the TX scheduler treats a
// real AP peer as a non-zero MACID. Env-overridable for A/B bisection.
static uint8_t mgmtMacId() {
    if (const char* m = std::getenv("DEVOURER_MGMT_MACID"))
        return (uint8_t)strtoul(m, nullptr, 0);
    return 1;
}
// Rate-id for the auth/assoc TX descriptor, BAND-AWARE — matches the kernel
// rtw_get_mgntframe_raid: non-CCK (5 GHz) => RATEID_IDX_G(7), 11B (2.4 GHz) =>
// RATEID_IDX_B(8). Pairs with mgmtTxRate(). DEVOURER_MGMT_RAID overrides for A/B.
static uint8_t mgmtRaid(int channel) {
    if (const char* r = std::getenv("DEVOURER_MGMT_RAID"))
        return (uint8_t)strtoul(r, nullptr, 0);
    return (channel > 14) ? 7 : 8;   // RATEID_IDX_G (5 GHz) | RATEID_IDX_B (2.4 GHz)
}
// Diagnostic: send auth/assoc as BMC=1 (broadcast TX desc — the monitor path that
// is PROVEN to radiate) while still addressed to the AP. If the AP then replies,
// the BMC=0 unicast TX path (ACK-wait/retry) was the non-radiating culprit.
static apfpv::StationFrameKind mgmtKind() {
    if (std::getenv("DEVOURER_AUTH_BMC"))
        return apfpv::StationFrameKind::BroadcastMgmt;
    return apfpv::StationFrameKind::Mgmt;
}

bool StationMode::sendAuthOpenSeq1(const MacAddr& self, const MacAddr& bssid) {
    Mac s, b; std::copy(self.b.begin(), self.b.end(), s.begin());
    std::copy(bssid.b.begin(), bssid.b.end(), b.begin());
    auto mpdu = BuildAuthOpenSeq1(s, b);
    std::vector<uint8_t> frame(TXDESC_8812 + mpdu.size(), 0);
    std::memcpy(frame.data() + TXDESC_8812, mpdu.data(), mpdu.size());
    FillStationTxDesc(frame.data(), (uint16_t)mpdu.size(), TXDESC_8812,
                      mgmtMacId(), mgmtKind(),
                      mgmtRaid(_rm.current_channel()), mgmtTxRate(_rm.current_channel()));
    return _send(frame);
}

bool StationMode::sendAssocRequest(const MacAddr& self, const MacAddr& bssid, const char* ssid) {
    Mac s, b; std::copy(self.b.begin(), self.b.end(), s.begin());
    std::copy(bssid.b.begin(), bssid.b.end(), b.begin());
    uint16_t rsnCaps = (uint16_t)((_pmf >= 1 ? 0x0080 : 0) | (_pmf >= 2 ? 0x0040 : 0)); // MFPC|MFPR
    auto mpdu = BuildAssocRequest(s, b, std::string(ssid), _pairwise, _group, rsnCaps);
    std::vector<uint8_t> frame(TXDESC_8812 + mpdu.size(), 0);
    std::memcpy(frame.data() + TXDESC_8812, mpdu.data(), mpdu.size());
    FillStationTxDesc(frame.data(), (uint16_t)mpdu.size(), TXDESC_8812,
                      mgmtMacId(), mgmtKind(),
                      mgmtRaid(_rm.current_channel()), mgmtTxRate(_rm.current_channel()));
    return _send(frame);
}

static inline uint8_t fc_type(uint16_t fc)    { return (fc >> 2) & 0x3; }
static inline uint8_t fc_subtype(uint16_t fc) { return (fc >> 4) & 0xF; }

void StationMode::onMgmtFrame(uint16_t fc, const MacAddr& a1, const MacAddr& a2) {
    if (fc_type(fc) != 0x0) return;          // mgmt only
    uint8_t sub = fc_subtype(fc);
    if (sub != 0x8) {
        SMLOG("rx mgmt subtype 0x%X", sub);   // log non-beacon mgmt (auth/assoc/deauth)
        if (std::getenv("DEVOURER_LOG_MGMT"))
            std::fprintf(stderr, "[mgmt-rx] sub=0x%X a1=%02x:%02x:%02x:%02x:%02x:%02x "
                         "a2=%02x:%02x:%02x:%02x:%02x:%02x\n", sub,
                         a1.b[0],a1.b[1],a1.b[2],a1.b[3],a1.b[4],a1.b[5],
                         a2.b[0],a2.b[1],a2.b[2],a2.b[3],a2.b[4],a2.b[5]);
    }
    // Only believe a response actually addressed to us (a1=self) FROM our AP (a2=bssid).
    // Overheard auth/assoc frames between other stations share the subtype and would
    // otherwise false-trigger the join (confirmed root cause of the bogus "Associating").
    if (!(a1.b == _expectSelf.b && a2.b == _expectBssid.b)) {
        if (std::getenv("DEVOURER_LOG_MGMT"))
            std::fprintf(stderr, "[mgmt-rx]   ^ ignored (not addressed to us from our AP)\n");
        return;
    }
    switch (sub) {
        case 0xB: _gotAuthResp = true; break;  // Auth
        case 0x1: _gotAssocOk  = true; break;  // Assoc-Resp
        case 0xC: case 0xA: _gotDeauth = true; break;  // Deauth/Disassoc
        default: break;
    }
}

StationMode::Result
StationMode::runProbe(const MacAddr& self, const MacAddr& bssid,
                      const char* ssid, int holdSeconds) {
    using namespace std::chrono;
    _expectSelf = self; _expectBssid = bssid;   // onMgmtFrame matches a1==self && a2==bssid
    // DAEMON-vs-DIRECT-CALL FIX: the IQK/LCK inside arm() does dozens of register reads
    // (control transfers). With the async RX worker thread live, those control reads
    // serialize behind the pending bulk-IN URBs on vhci/WinUSB (same root cause as the
    // bulk-OUT wedge) -> the IQK ready-poll is slowed/garbled -> the cal converges only
    // ~2/5. Drain the RX pool for the cal so its control I/O is clean, like the kernel
    // (which runs cal with no userspace RX thread contending). Resume re-arms RX so the
    // auth-response that follows is still caught.
    bool pauseForCal = !std::getenv("DEVOURER_NO_PAUSE_CAL");
    if (pauseForCal) _dev.pauseAsyncRx();
    arm(self, bssid);
    if (pauseForCal) _dev.resumeAsyncRx();
    // ACK-DRIVEN VERIFY: read back the RX-filter state the chip holds after arm(). The auth
    // radiates every run (FIFO=4095) yet the AP reply is missed in silent runs — a raced
    // RCR/MSR/BSSID write would silently drop that reply. Compare silent vs connecting.
    try {
        uint32_t rcr=_dev.rtw_read32(0x608); uint8_t msr=_dev.rtw_read8(0x102);
        uint8_t b0=_dev.rtw_read8(0x618),b1=_dev.rtw_read8(0x619),b2=_dev.rtw_read8(0x61a),
                b3=_dev.rtw_read8(0x61b),b4=_dev.rtw_read8(0x61c),b5=_dev.rtw_read8(0x61d);
        uint8_t m0=_dev.rtw_read8(0x610),m1=_dev.rtw_read8(0x611),m2=_dev.rtw_read8(0x612),
                m3=_dev.rtw_read8(0x613),m4=_dev.rtw_read8(0x614),m5=_dev.rtw_read8(0x615);
        fprintf(stderr,"[arm-verify] RCR=0x%08x MSR=0x%02x BSSID=%02x:%02x:%02x:%02x:%02x:%02x "
                "MACID=%02x:%02x:%02x:%02x:%02x:%02x SELF=%02x:%02x:%02x:%02x:%02x:%02x\n",
                rcr,msr,b0,b1,b2,b3,b4,b5,m0,m1,m2,m3,m4,m5,
                self.b[0],self.b[1],self.b[2],self.b[3],self.b[4],self.b[5]);
    } catch (...) {}
    SMLOG("arm: self %02x:%02x:%02x:%02x:%02x:%02x -> bssid %02x:%02x:%02x:%02x:%02x:%02x",
          self.b[0],self.b[1],self.b[2],self.b[3],self.b[4],self.b[5],
          bssid.b[0],bssid.b[1],bssid.b[2],bssid.b[3],bssid.b[4],bssid.b[5]);
    if (!_armed) return Result::Error;
    // CRITICAL TX-POWER FIX: arm()'s channel-set runs PHY_SetTxPowerLevel8812, which resets
    // power to the EEPROM by-rate index (~0 here = on-air SILENCE). Any earlier SetTxPower
    // (ApfpvStation connect-path) is therefore overridden, so the auth keyed the PA at zero
    // power and the AP's hostapd NEVER heard it (proven via AP-side capture), while the
    // beacon path radiated at -52 dBm because its SetTxPower is the last power write.
    // Re-apply a solid uniform index AFTER the channel-set so the auth actually radiates.
    { uint8_t p = 40; if (const char* e = std::getenv("DEVOURER_TX_PWR_IDX")) p = (uint8_t)atoi(e);
      try { _rm.SetTxPower(p); } catch (...) {} }
    // DEAUTH-BEFORE-AUTH: clear any stale association the AP still holds for our MAC from a
    // prior (possibly incomplete) attempt. Without it the AP ignores our re-auth (it still
    // thinks we're associated) and we stall at Authenticating on alternate back-to-back
    // connects. This is exactly what wpa_supplicant sends on (re)connect.
    if (!std::getenv("DEVOURER_SKIP_DEAUTH")) {
        uint8_t m[26] = {0xC0,0x00, 0x00,0x00};       // FC=mgmt/deauth, duration
        std::memcpy(m+4,  bssid.b.data(), 6);          // a1 = AP
        std::memcpy(m+10, self.b.data(),  6);          // a2 = self
        std::memcpy(m+16, bssid.b.data(), 6);          // a3 = AP
        m[24]=0x03; m[25]=0x00;                         // reason 3 (STA leaving)
        std::vector<uint8_t> df(TXDESC_8812 + sizeof(m), 0);
        std::memcpy(df.data()+TXDESC_8812, m, sizeof(m));
        FillStationTxDesc(df.data(), (uint16_t)sizeof(m), TXDESC_8812, mgmtMacId(), mgmtKind(),
                          mgmtRaid(_rm.current_channel()), mgmtTxRate(_rm.current_channel()));
        _send(df);
        std::this_thread::sleep_for(milliseconds(60));  // let the AP drop the old STA
    }
    if (_onPhase) _onPhase(1);                         // -> Authenticating
    bool sent = sendAuthOpenSeq1(self, bssid);
    // RF-front-end + TX-path state at the auth TX (fires every arm, sent or not) to
    // catch the "drains FIFO but nothing radiates" silence: RFE (antenna TR switch,
    // BB Page C1 via 0x82c bit31), ANT sel, TXPAUSE, CCA, BB path-A TX enable.
    try {
        uint32_t pc = _dev.rtw_read32(0x082c);
        _dev.rtw_write32(0x082c, pc & ~0x80000000u);
        uint32_t rfeA = _dev.rtw_read32(0x0cb8);
        _dev.rtw_write32(0x082c, pc | 0x80000000u);   // Page C1 for TX-IQC matrix
        uint32_t txY = _dev.rtw_read32(0x0ccc) & 0x7ff, txX = _dev.rtw_read32(0x0cd4) & 0x7ff;
        _dev.rtw_write32(0x082c, pc);
        // TXiqcX=0x200,TXiqcY=0x0 = IQK-default (path-A TX-cal did NOT converge this arm).
        fprintf(stderr, "[auth-tx-rf] sent=%d CR=0x%04x TXPAUSE=0x%02x ANT808=0x%02x CCA838=0x%08x RFEcb8=0x%08x TXiqcX=0x%03x TXiqcY=0x%03x BBtxA=0x%08x\n",
                (int)sent, _dev.rtw_read16(0x0100), _dev.rtw_read8(0x0522), _dev.rtw_read8(0x0808),
                _dev.rtw_read32(0x0838), rfeA, txX, txY, _dev.rtw_read32(0x0c04));
    } catch (...) { fprintf(stderr, "[auth-tx-rf] register read THREW\n"); }
    SMLOG("auth-req tx sent=%d, waiting 3s for auth-resp...", sent ? 1 : 0);
    if (!sent) return Result::Error;

    auto t0 = steady_clock::now();
    auto lastTx = t0;
    int retx = 0;
    while (!_gotAuthResp && !_gotDeauth && steady_clock::now() - t0 < seconds(3)) {
        std::this_thread::sleep_for(milliseconds(50));
        // Retransmit the auth like the kernel MLME (it retries ~3x at ~200ms). If our
        // single auth-req flickered off-air on this arm, another frame may radiate and
        // reach the AP. Cheap, kernel-faithful, and directly tests per-frame TX flicker.
        if (!_gotAuthResp && retx < 5 &&
            steady_clock::now() - lastTx > milliseconds(350)) {
            sendAuthOpenSeq1(self, bssid);
            lastTx = steady_clock::now();
            ++retx;
        }
    }
    if (!_gotAuthResp) {
        try {
            fprintf(stderr, "[auth-fail] CR=0x%04x TXPKT_EMPTY=0x%04x HISR=0x%08x FIFOPAGE0x200=0x%08x REG0x10c=0x%04x\n",
                    _dev.rtw_read16(0x0100), _dev.rtw_read16(0x041a), _dev.rtw_read32(0x00b4),
                    _dev.rtw_read32(0x0200), _dev.rtw_read16(0x010c));
            // RF front-end state — RFE (antenna TR switch, BB Page C1 via 0x82c bit31),
            // antenna sel, TXPAUSE, CCA. 0 RFE = "drains FIFO but nothing radiates".
            uint32_t pc = _dev.rtw_read32(0x082c);
            _dev.rtw_write32(0x082c, pc & ~0x80000000u);
            uint32_t rfeA = _dev.rtw_read32(0x0cb8), rfeB = _dev.rtw_read32(0x0eb8);
            _dev.rtw_write32(0x082c, pc);
            fprintf(stderr, "[auth-fail-rf] TXPAUSE0x522=0x%02x ANT808=0x%02x CCA838=0x%08x RFEcb8=0x%08x RFEeb8=0x%08x BBtxA_c04=0x%08x\n",
                    _dev.rtw_read8(0x0522), _dev.rtw_read8(0x0808), _dev.rtw_read32(0x0838),
                    rfeA, rfeB, _dev.rtw_read32(0x0c04));
        } catch (...) { fprintf(stderr, "[auth-fail] chip register read THREW -> whole USB wedged (not just bulk-OUT)\n"); }
        SMLOG("NO auth-resp (deauth=%d)", _gotDeauth.load()); return Result::TXFAIL_NoAuthResp;
    }
    SMLOG("got auth-resp! sending assoc-req...");

    if (_onPhase) _onPhase(2);                          // -> Associating
    std::this_thread::sleep_for(milliseconds(100));
    if (!sendAssocRequest(self, bssid, ssid)) return Result::Error;

    auto t1 = steady_clock::now();
    while (!_gotAssocOk && !_gotDeauth && steady_clock::now() - t1 < seconds(3))
        std::this_thread::sleep_for(milliseconds(50));
    if (_gotDeauth)   return Result::NOGO_Deauthed;
    if (!_gotAssocOk) return Result::NOGO_NoAssocResp;

    // Associated! NOW become a connected station (MSR->STATION + connected H2C),
    // matching the kernel's post-assoc order. The 4-way handshake + data follow.
    becomeStation(bssid);

    auto h0 = steady_clock::now();
    while (steady_clock::now() - h0 < seconds(holdSeconds)) {
        if (_gotDeauth) return Result::NOGO_Deauthed;
        std::this_thread::sleep_for(milliseconds(100));
    }
    return Result::GO_LinkHeld;
}


// ---- beacon scan: discover BSSID + channel + RSN (security/discovery parity) -
void StationMode::onScanFrame(const uint8_t* frame, size_t len) {
    ApInfo info;
    if (ScanProbe::parseBeacon(frame, len, _scanSsid, info)) {
        if (!_scanResult.found || info.rssi > _scanResult.rssi) _scanResult = info;
    }
}

ApInfo StationMode::scanForSsid(const char* ssid, int channelHint, int perChannelMs) {
    using namespace std::chrono;
    _scanSsid = ssid; _scanResult = ApInfo{};
    // Order = likelihood for a LEGAL APFPV link first, then catch-all:
    //   1) hint (the configured/last APFPV channel)
    //   2) 5.2 GHz UNII-1 (36/40/44/48) — the legal DE 200 mW @ 20 MHz APFPV band
    //      (PSD cap 10 mW/MHz x 20 MHz = 200 mW). A compliant VTX lives here.
    //   3) the rest of 5 GHz (UNII-2A/2C DFS, UNII-3 149-165) + common 2.4 GHz,
    //      so we can still find a test hotspot/router parked off the legal band.
    int channels[] = { channelHint,
                       36, 40, 44, 48,                 // UNII-1 — legal DE 200 mW APFPV
                       1, 6, 11,                       // 2.4 GHz common (test hotspots)
                       52, 56, 60, 64,                 // UNII-2A (DFS)
                       149, 153, 157, 161, 165 };      // UNII-3
    for (int ch : channels) {
        if (ch <= 0) continue;
        _scanResult = ApInfo{};   // reset per channel — don't carry a bleed match over
        _rm.set_channel_bwmode((uint8_t)ch, 0, CHANNEL_WIDTH_20);  // tune radio (devourer API)
        auto t0 = steady_clock::now();
        while (steady_clock::now() - t0 < milliseconds(perChannelMs)) {
            // Accept only a CLEAN on-channel reception: the beacon's DS-param
            // channel must equal the tuned channel. This rejects 2.4GHz adjacent-
            // channel bleed (hearing a ch6 AP while tuned to ch1) that otherwise
            // returns the WRONG channel -> we arm off-channel -> auth never ACKs.
            if (_scanResult.found && (_scanResult.channel == ch || _scanResult.channel == 0)) {
                _scanResult.channel = ch; return _scanResult;
            }
            std::this_thread::sleep_for(milliseconds(20));
        }
    }
    return _scanResult;   // .found == false if not seen
}

} // namespace apfpv