#include "PhydmWatchdog.h"

#include "RadioManagementModule.h"
#include <android/log.h>   // NDK on Android, compat stderr shim on host (see WiFiDriver/compat)

#include <algorithm>
#include <chrono>

namespace {

/* Phydm AC FA counter register addresses, from
 * `hal/phydm/phydm_regdefine11ac.h`. */
constexpr uint16_t kRegOfdmFaType1 = 0xFCC; /* fast_fsync hi 16 */
constexpr uint16_t kRegOfdmFaType2 = 0xFD0; /* sb_search_fail lo 16 */
constexpr uint16_t kRegOfdmFaType3 = 0xFBC; /* parity_fail / rate_illegal */
constexpr uint16_t kRegOfdmFaType4 = 0xFC0; /* crc8_fail / mcs_fail */
constexpr uint16_t kRegOfdmFaType5 = 0xFC4; /* vht_crc8_fail */
constexpr uint16_t kRegOfdmFaType6 = 0xFC8; /* vht_mcs_fail */
constexpr uint16_t kRegOfdmFail = 0xF48;    /* OFDM FA count */
constexpr uint16_t kRegCckFa = 0xA5C;       /* CCK FA count */
constexpr uint16_t kRegCckCcaCnt = 0xF08;   /* CCK/OFDM CCA count */
constexpr uint16_t kRegCckCrc32Cnt = 0xF04;
constexpr uint16_t kRegVhtCrc32Cnt = 0xF0c;
constexpr uint16_t kRegHtCrc32Cnt = 0xF10;
constexpr uint16_t kRegOfdmCrc32Cnt = 0xF14;
constexpr uint16_t kRegBbRxPath = 0x808; /* BIT(28) = CCK enable */

constexpr uint32_t kMaskDWord = 0xFFFFFFFF;
constexpr uint32_t kMaskLWord = 0x0000FFFF;
constexpr uint32_t kBit28 = 1u << 28;
constexpr uint32_t kBit17 = 1u << 17;
constexpr uint32_t kBit15 = 1u << 15;
constexpr uint32_t kBit0 = 1u << 0;

/* Watchdog tick interval. Upstream uses 2s on Linux (CE) per
 * `ADAPTIVITY_INTERVAL` / phydm_interface.c. */
constexpr auto kTickInterval = std::chrono::seconds(2);

} // namespace

/* Connected-mode link state (see header). Default monitor mode. */
std::atomic<bool> PhydmWatchdog::_s_linked{false};
std::atomic<int> PhydmWatchdog::_s_rssiDbm{-128};
std::atomic<int> PhydmWatchdog::_s_uplinkRate{-1};

void PhydmWatchdog::SetLinkRssi(int rssi_dbm) {
  _s_rssiDbm.store(rssi_dbm, std::memory_order_relaxed);
  _s_linked.store(true, std::memory_order_relaxed);
}
void PhydmWatchdog::SetUnlinked() {
  _s_linked.store(false, std::memory_order_relaxed);
  _s_uplinkRate.store(-1, std::memory_order_relaxed);
}
int PhydmWatchdog::RssiDbm() { return _s_rssiDbm.load(std::memory_order_relaxed); }

void PhydmWatchdog::OnUplinkRate(uint8_t rate_idx) {
  _s_uplinkRate.store((int)rate_idx, std::memory_order_relaxed);
}
uint8_t PhydmWatchdog::UplinkRate() {
  int r = _s_uplinkRate.load(std::memory_order_relaxed);
  return r < 0 ? 0xff : (uint8_t)r;
}

/* CFO tracking accumulators (fed per-RX-packet from FrameParser). */
std::atomic<int> PhydmWatchdog::_s_cfo_sum[2]{};
std::atomic<unsigned> PhydmWatchdog::_s_cfo_cnt[2]{};
std::atomic<unsigned> PhydmWatchdog::_s_cfo_pkt{0};

void PhydmWatchdog::AddCfo(int cfo_a, int cfo_b) {
  _s_cfo_sum[0].fetch_add(cfo_a, std::memory_order_relaxed);
  _s_cfo_cnt[0].fetch_add(1, std::memory_order_relaxed);
  _s_cfo_sum[1].fetch_add(cfo_b, std::memory_order_relaxed);
  _s_cfo_cnt[1].fetch_add(1, std::memory_order_relaxed);
  _s_cfo_pkt.fetch_add(1, std::memory_order_relaxed);
}

PhydmWatchdog::PhydmWatchdog(RtlUsbAdapter device,
                             std::shared_ptr<EepromManager> eepromManager,
                             RadioManagementModule *radio, Logger_t logger)
    : _device(device), _eepromManager(eepromManager), _radio(radio),
      _logger(logger) {}

PhydmWatchdog::~PhydmWatchdog() { Stop(); }

void PhydmWatchdog::Start() {
  bool expected = false;
  if (!_running.compare_exchange_strong(expected, true)) {
    return; /* already running */
  }
  _stop.store(false);
  _thread = std::thread([this]() { ThreadLoop(); });
}

void PhydmWatchdog::Stop() {
  bool expected = true;
  if (!_running.compare_exchange_strong(expected, false)) {
    return; /* not running */
  }
  _stop.store(true);
  if (_thread.joinable()) {
    _thread.join();
  }
}

void PhydmWatchdog::ThreadLoop() {
  /* Wake every kTickInterval and run TickOnce. Interruptible via
   * _stop. Use short polled sleeps (200ms) so Stop() returns
   * quickly even mid-interval. */
  auto next_tick = std::chrono::steady_clock::now() + kTickInterval;
  while (!_stop.load()) {
    if (std::chrono::steady_clock::now() >= next_tick) {
      TickOnce();
      next_tick = std::chrono::steady_clock::now() + kTickInterval;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
}

void PhydmWatchdog::TickOnce() {
  /* Read FA counters (no-op if BB isn't running yet — counters
   * read zero). Then reset the counter latches so the next tick
   * captures only the delta. */
  FaCnt fa{};
  ReadFaCountersAc(fa);
  _lastFaCnt = fa;
  ResetFaCountersAc();

  /* DIG (Dynamic Initial Gain) — walk per-path IGI based on FA
   * count. Reads BB 0xc50 byte 0 on the first tick to seed
   * `cur_ig_value`, then on subsequent ticks adjusts and writes
   * to all 4 paths (paths C/D writes are 8814-only; harmless
   * write-only on 8812/8821). */
  if (!_digInitialised) {
    DigInit();
    _digInitialised = true;
  }
  DigTick(fa.cnt_all);

  /* CFO tracking (phydm_cfo_tracking port). Opt-in — a wrong crystal cap
   * detunes the radio, so gate it until validated. */
  if (std::getenv("DEVOURER_CFO_TRACK")) {
    CfoTick();
  }
}

void PhydmWatchdog::ReadFaCountersAc(FaCnt &out) {
  /* Port of `phydm_fa_cnt_statistics_ac` (phydm_dig.c:1421).
   * Reads OFDM/CCK FA + CCA + CRC32 counters from page-F BB
   * registers. Fields not needed for the watchdog's own logic are
   * skipped; the canonical phydm struct populates ~14 counters
   * total and we cover the same set. */
  uint32_t v = 0;

  /* OFDM FA breakdown — kept for diagnostics, not used by the
   * current minimal watchdog logic. */
  (void)_radio->phy_query_bb_reg_public(kRegOfdmFaType1, kMaskDWord);
  (void)_radio->phy_query_bb_reg_public(kRegOfdmFaType2, kMaskDWord);
  (void)_radio->phy_query_bb_reg_public(kRegOfdmFaType3, kMaskDWord);
  (void)_radio->phy_query_bb_reg_public(kRegOfdmFaType4, kMaskDWord);
  (void)_radio->phy_query_bb_reg_public(kRegOfdmFaType5, kMaskDWord);
  (void)_radio->phy_query_bb_reg_public(kRegOfdmFaType6, kMaskDWord);

  /* OFDM/CCK FA counts. */
  out.cnt_ofdm_fail =
      _radio->phy_query_bb_reg_public(kRegOfdmFail, kMaskLWord);
  out.cnt_cck_fail =
      _radio->phy_query_bb_reg_public(kRegCckFa, kMaskLWord);

  /* CCA counts. */
  v = _radio->phy_query_bb_reg_public(kRegCckCcaCnt, kMaskDWord);
  out.cnt_ofdm_cca = (v & 0xffff0000) >> 16;
  out.cnt_cck_cca = v & 0xffff;

  /* CRC32 counters. */
  v = _radio->phy_query_bb_reg_public(kRegCckCrc32Cnt, kMaskDWord);
  out.cnt_cck_crc32_error = (v & 0xffff0000) >> 16;
  out.cnt_cck_crc32_ok = v & 0xffff;

  v = _radio->phy_query_bb_reg_public(kRegOfdmCrc32Cnt, kMaskDWord);
  out.cnt_ofdm_crc32_error = (v & 0xffff0000) >> 16;
  out.cnt_ofdm_crc32_ok = v & 0xffff;

  v = _radio->phy_query_bb_reg_public(kRegHtCrc32Cnt, kMaskDWord);
  out.cnt_ht_crc32_error = (v & 0xffff0000) >> 16;
  out.cnt_ht_crc32_ok = v & 0xffff;

  v = _radio->phy_query_bb_reg_public(kRegVhtCrc32Cnt, kMaskDWord);
  out.cnt_vht_crc32_error = (v & 0xffff0000) >> 16;
  out.cnt_vht_crc32_ok = v & 0xffff;

  /* Cumulative FA + CCA. CCK bits live in 0x808 BIT(28); if set,
   * BB is using CCK so total includes CCK + OFDM. Otherwise OFDM
   * only. */
  const bool cck_enable =
      _radio->phy_query_bb_reg_public(kRegBbRxPath, kBit28) != 0;
  if (cck_enable) {
    out.cnt_all = out.cnt_ofdm_fail + out.cnt_cck_fail;
    out.cnt_cca_all = out.cnt_ofdm_cca + out.cnt_cck_cca;
  } else {
    out.cnt_all = out.cnt_ofdm_fail;
    out.cnt_cca_all = out.cnt_ofdm_cca;
  }
}

void PhydmWatchdog::ResetFaCountersAc() {
  /* Port of `phydm_false_alarm_counter_reg_reset` AC branch
   * (phydm_dig.c:1287-1298). Pulses the OFDM/CCK FA counter
   * reset bits, then resets the PMAC/PHY counter via
   * `phydm_reset_bb_hw_cnt` (R_0xb58 BIT(0)). */
  /* OFDM FA counter reset (R_0x9a4 BIT(17) toggle). */
  _device.phy_set_bb_reg(0x9a4, kBit17, 1);
  _device.phy_set_bb_reg(0x9a4, kBit17, 0);

  /* CCK FA counter reset (R_0xa2c BIT(15) toggle). */
  _device.phy_set_bb_reg(0xa2c, kBit15, 0);
  _device.phy_set_bb_reg(0xa2c, kBit15, 1);

  /* All-counter reset (R_0xb58 BIT(0) toggle). */
  _device.phy_set_bb_reg(0xb58, kBit0, 1);
  _device.phy_set_bb_reg(0xb58, kBit0, 0);
}

PhydmWatchdog::FaCnt PhydmWatchdog::LastFaCnt() const { return _lastFaCnt; }

void PhydmWatchdog::DigInit() {
  /* Port of `phydm_dig_init` (phydm_dig.c:726). Reads current
   * BB 0xc50 byte 0 as the initial IGI value. Bounds match the
   * Jaguar AC family monitor-mode (!is_linked) configuration:
   * coverage 0x1c..0x26, with dig_max_of_min = 0x2a as the upper
   * bound when nothing's linked. */
  _cur_ig_value =
      static_cast<uint8_t>(_radio->phy_query_bb_reg_public(0xc50, 0xff));
  _rx_gain_range_max = _dig_max_of_min;
  _rx_gain_range_min = _dm_dig_min;
  _logger->info("PhydmWatchdog::DigInit cur_ig=0x{:02x} bounds=[0x{:02x},0x{:02x}]",
                unsigned(_cur_ig_value),
                unsigned(_rx_gain_range_min),
                unsigned(_rx_gain_range_max));
}

void PhydmWatchdog::DigTick(uint32_t fa_cnt) {
  /* Port of `phydm_dig` (phydm_dig.c:1066), monitor-mode subset.
   * Always !is_linked since devourer doesn't track link state.
   * `phydm_dig_abs_boundary_decision`: dm_dig_max = COVERAGR (0x26),
   * dm_dig_min = COVERAGE (0x1c). `phydm_dig_dym_boundary_decision`:
   * rx_gain_range_{max,min} stay at {dig_max_of_min, dm_dig_min}.
   * `phydm_new_igi_by_fa`: step={2,1,2}, FA thresholds={250,500,750}.
   *
   * Per `phydm_get_new_igi` (phydm_dig.c:952), monitor-mode walk:
   *   fa > 750 → igi += 2 (saturate)
   *   fa > 500 → igi += 1
   *   fa < 250 → igi -= 2
   * Then clamp to [rx_gain_range_min, rx_gain_range_max]. */
  constexpr uint16_t kFaTh0 = 250;
  constexpr uint16_t kFaTh1 = 500;
  constexpr uint16_t kFaTh2 = 750;
  constexpr uint8_t kStepUp1 = 2; /* fa > kFaTh2 */
  constexpr uint8_t kStepUp2 = 1; /* fa > kFaTh1 */
  constexpr uint8_t kStepDown = 2; /* fa < kFaTh0 */

  /* Refresh bounds from abs_boundary_decision + dym_boundary_decision
   * each tick. Two regimes:
   *
   *   monitor (!is_linked, wfb-ng): coverage bounds — dm_dig_max=0x26,
   *   floor=0x1c, ceiling=dig_max_of_min(0x2a). Keeps gain high for
   *   long-range sensitivity at the cost of false alarms.
   *
   *   connected (is_linked, station): phydm connected bounds —
   *   dm_dig_max=0x3e, dm_dig_min=0x20, and the dynamic floor tracks
   *   RSSI: rx_gain_range_min = clamp(rssi_dBm+100, 0x20, 0x3e). The
   *   floor-clamp below then snaps cur_ig straight to that operating
   *   point (e.g. -45 dBm → 0x37), matching the kernel 88XXau driver
   *   and avoiding the strong-signal over-gain that storms the FA
   *   counter and makes the AP rate-cap us. */
  if (_s_linked.load(std::memory_order_relaxed)) {
    _dm_dig_max = 0x3e;
    _dm_dig_min = 0x20;
    int rssi_val = _s_rssiDbm.load(std::memory_order_relaxed) + 100;
    if (rssi_val < _dm_dig_min) rssi_val = _dm_dig_min;
    if (rssi_val > _dm_dig_max) rssi_val = _dm_dig_max;
    _rx_gain_range_min = static_cast<uint8_t>(rssi_val);
    _rx_gain_range_max = _dm_dig_max;
  } else {
    _dm_dig_max = 0x26;
    _dm_dig_min = 0x1c;
    _rx_gain_range_max = _dig_max_of_min;
    _rx_gain_range_min = _dm_dig_min;
  }

  uint8_t new_igi = _cur_ig_value;
  if (fa_cnt > kFaTh2) {
    new_igi += kStepUp1;
  } else if (fa_cnt > kFaTh1) {
    new_igi += kStepUp2;
  } else if (fa_cnt < kFaTh0) {
    if (new_igi >= kStepDown) {
      new_igi -= kStepDown;
    } else {
      new_igi = 0;
    }
  }

  if (new_igi < _rx_gain_range_min) {
    new_igi = _rx_gain_range_min;
  }
  if (new_igi > _rx_gain_range_max) {
    new_igi = _rx_gain_range_max;
  }

  if (new_igi != _cur_ig_value) {
    _logger->debug("PhydmWatchdog::DigTick fa={} igi 0x{:02x}->0x{:02x}",
                   fa_cnt, unsigned(_cur_ig_value), unsigned(new_igi));
    DigWriteIgi(new_igi);
    _cur_ig_value = new_igi;
  } else {
    /* Re-write the same value to ensure the BB reg is in sync
     * with our cached cur_ig_value (matters on first tick when
     * BB-init left a different value than `phydm_SetIgiFloor_Jaguar`
     * later overwrote). */
    DigWriteIgi(new_igi);
  }
}

void PhydmWatchdog::DigWriteIgi(uint8_t igi) {
  /* Port of `phydm_write_dig_reg_c50` (phydm_dig.c:501). Writes
   * the IGI byte to all populated path-IGI registers. Path C/D
   * writes are 8814-only but writing them on 8812/8821 is
   * harmless: those chips' BB regs at 0x1850/0x1a50 are reserved
   * and ignore writes.
   *
   * NOTE: this duplicates the chip-family path-count check that
   * RadioManagementModule does, but we don't have the EEPROM
   * version_id easily accessible from here. Writing the unused
   * paths is a no-op on non-8814. */
  _device.phy_set_bb_reg(0xc50, 0xff, igi); /* path A — rA_IGI_Jaguar */
  _device.phy_set_bb_reg(0xe50, 0xff, igi); /* path B — rB_IGI_Jaguar */
  _device.phy_set_bb_reg(0x1850, 0xff, igi); /* path C — 8814 only */
  _device.phy_set_bb_reg(0x1a50, 0xff, igi); /* path D — 8814 only */
}

void PhydmWatchdog::SetCrystalCap(uint8_t crystal_cap) {
  /* 8812: REG 0x2C bits[30:25] = bits[24:19] = crystal_cap (6-bit). Read-
   * modify-write the MAC reg. (phydm_set_crystal_cap_reg, 8812 branch.) */
  crystal_cap &= 0x3f;
  uint32_t v = _device.rtw_read32(0x2c);
  v &= ~0x7FF80000u;
  v |= ((uint32_t)crystal_cap << 25) | ((uint32_t)crystal_cap << 19);
  _device.rtw_write32(0x2c, v);
  _crystal_cap = crystal_cap;
}

void PhydmWatchdog::CfoTick() {
  /* Port of phydm_cfo_tracking (phydm_cfotracking.c:370). Average the per-path
   * CFO tail accumulated from RX phystatus, then step the crystal cap +/-1 to
   * keep |CFO| under the stop threshold (10kHz), with a 20kHz enable hysteresis. */
  if (!_cfo_inited) {
    uint32_t v = _device.rtw_read32(0x2c);
    _crystal_cap = (uint8_t)((v >> 25) & 0x3f);   /* current bits[30:25] */
    _crystal_cap_def = _crystal_cap;
    _cfo_inited = true;
    _logger->info("CfoTrack init crystal_cap=0x{:02x}", unsigned(_crystal_cap));
  }
  /* Only track on a live single-peer link (matches is_linked & one_entry_only). */
  if (!_s_linked.load(std::memory_order_relaxed)) return;

  unsigned pkt = _s_cfo_pkt.load(std::memory_order_relaxed);
  if (pkt == _cfo_pkt_pre) return;   /* no new packets this interval */
  _cfo_pkt_pre = pkt;

  /* CFO_HW_RPT_2_KHZ(v) = (v<<1)+(v>>1) = v*2.5. Average per path, keep sign. */
  int cfo_path_sum = 0, valid = 0;
  for (int i = 0; i < 2; i++) {
    unsigned cnt = _s_cfo_cnt[i].exchange(0, std::memory_order_relaxed);
    int sum = _s_cfo_sum[i].exchange(0, std::memory_order_relaxed);
    if (cnt == 0) continue;
    valid++;
    int a = sum < 0 ? -sum : sum;
    int khz = ((a << 1) + (a >> 1)) / (int)cnt;
    cfo_path_sum += (sum < 0) ? -khz : khz;
  }
  if (valid == 0) return;
  int cfo_avg = (valid >= 2) ? cfo_path_sum / valid : cfo_path_sum;

  __android_log_print(4, "apfpv-scan", "CfoTrack: cfo_avg=%dkHz paths=%d cap=0x%02x adjust=%d (pkts=%u)",
                      cfo_avg, valid, (unsigned)_crystal_cap, _cfo_is_adjust ? 1 : 0, pkt - 0);

  if (!_cfo_is_adjust) {
    if (cfo_avg > 20 || cfo_avg < -20) _cfo_is_adjust = true;   /* CFO_TRK_ENABLE_TH */
  } else {
    if (cfo_avg < 10 && cfo_avg > -10) _cfo_is_adjust = false;  /* CFO_TRK_STOP_TH */
  }
  if (_cfo_is_adjust) {
    int cap = _crystal_cap;
    // The kernel steps +/-1 per tick because its crystal cap starts factory-correct
    // (~0 CFO). Ours can start far off (e.g. 124kHz when 0x2C was clobbered to a low
    // cap), so converge proportionally — ~3.3kHz per cap step on the 8812 — to reach
    // the <10kHz lock in a few ticks instead of ~2 minutes.
    int absavg = cfo_avg < 0 ? -cfo_avg : cfo_avg;
    int step = absavg > 60 ? 8 : absavg > 30 ? 4 : absavg > 15 ? 2 : 1;
    if (cfo_avg > 10) cap += step;
    else if (cfo_avg < -10) cap -= step;
    if (cap > 0x3f) cap = 0x3f;
    if (cap < 0) cap = 0;
    if ((uint8_t)cap != _crystal_cap) {
      _logger->info("CfoTrack cfo_avg={}kHz cap 0x{:02x}->0x{:02x}",
                    cfo_avg, unsigned(_crystal_cap), unsigned(cap));
      SetCrystalCap((uint8_t)cap);
    }
  }
}
