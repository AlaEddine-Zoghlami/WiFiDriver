#ifndef PHYDM_WATCHDOG_H
#define PHYDM_WATCHDOG_H

#include "EepromManager.h"
#include "RtlUsbAdapter.h"
#include "logger.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <thread>

class RadioManagementModule;

/* Periodic phydm DM watchdog — runs every ~2s to drive dynamic
 * management modules (FA counter statistics, DIG, RSSI tracking,
 * etc.) the way upstream's `phydm_watchdog` does.
 *
 * Upstream `phydm_watchdog` (hal/phydm/phydm.c:1985) chains together:
 *   phydm_phy_info_update, phydm_rssi_monitor_check,
 *   phydm_false_alarm_counter_statistics, phydm_noisy_detection,
 *   phydm_dig, phydm_cck_pd_th, phydm_adaptivity, phydm_ra_info_watchdog,
 *   phydm_tx_path_diversity, phydm_cfo_tracking, phydm_dynamic_tx_power,
 *   odm_antenna_diversity, phydm_beamforming_watchdog, halrf_watchdog,
 *   phydm_primary_cca, ...
 *
 * Devourer's port scope (this header):
 *   - FA counter statistics for the AC family (8812/8814/8821) —
 *     reads BB OFDM/CCK FA+CCA counters at 0xfcc..0xfd0, resets at
 *     tick boundary so successive ticks see only the delta.
 *
 * Out of scope (added as separate ports):
 *   - RSSI monitor / CFO tracking / adaptivity — depend on TX/RX
 *     activity which devourer drives via its own paths.
 *   - Beamforming, antenna diversity — out of scope for monitor mode.
 *
 * Thread model: spawns a single background `std::thread` that wakes
 * every 2s, runs `TickOnce()`, sleeps again. Stops cleanly on
 * destruction (sets _stop, joins). `TickOnce()` is also callable
 * directly (used at end-of-init for an immediate first cycle so the
 * canary capture sees post-watchdog state). */
class PhydmWatchdog {
public:
  PhydmWatchdog(RtlUsbAdapter device,
                std::shared_ptr<EepromManager> eepromManager,
                RadioManagementModule *radio, Logger_t logger);
  ~PhydmWatchdog();

  /* Spawn the watchdog thread. Idempotent. */
  void Start();
  /* Signal stop + join. Idempotent. Called from destructor. */
  void Stop();
  /* Run one watchdog cycle synchronously on the calling thread. */
  void TickOnce();

  /* Link-state / RSSI hook for connected-mode DIG.
   *
   * Devourer's DIG defaults to phydm's *monitor-mode* (!is_linked)
   * boundaries [0x1c, 0x2a] — correct for wfb-ng long-range RX where
   * you trade false alarms for sensitivity. But a *station* linked to
   * a strong local AP needs phydm's *connected-mode* boundaries
   * [0x20, 0x3e] with the IGI floor tracking RSSI:
   *     rx_gain_range_min = clamp(rssi_val, dm_dig_min, dm_dig_max)
   *     rssi_val ≈ rssi_dBm + 100   (phydm 0..100 scale)
   * so e.g. -45 dBm → IGI 0x37 — exactly what the kernel 88XXau driver
   * converges to. With monitor bounds our IGI was clamped at 0x2a, far
   * below 0x37: front-end over-gained → strong-signal saturation →
   * false-alarm storm (fa≈900/2s) → OFDM CRC errors → AP rate-caps us
   * (30 Mbps vs the kernel's 72). The station feeds its live RX RSSI
   * here so DIG jumps the IGI floor straight to the right operating
   * point. Static (one dongle/watchdog per process); set false/unset
   * to restore monitor bounds for wfb-ng. */
  static void SetLinkRssi(int rssi_dbm);
  static void SetUnlinked();

  /* CFO (carrier-frequency-offset) tracking — port of phydm_cfo_tracking.
   * Fed per-RX-packet from FrameParser with the phystatus path-A/B CFO tail
   * (s8, s(8,7)); the watchdog averages it each tick and steps the crystal cap
   * (REG 0x2C) by +/-1 to pull |CFO| under 10kHz. Our oscillator drifts vs the
   * AP's; uncorrected CFO smears the dense MCS8 constellation → ~5-9% RX PER
   * (kernel <1%) → the AP throttles our A-MPDU. We ported only DIG before; this
   * is the missing piece. Gated DEVOURER_CFO_TRACK (opt-in) for safe A/B since a
   * bad cap detunes the radio. Static: one dongle/watchdog per process. */
  static void AddCfo(int cfo_a, int cfo_b);

  /* Most-recent FA counter snapshot — exposed for diagnostics /
   * future DIG integration. */
  struct FaCnt {
    uint32_t cnt_ofdm_fail;
    uint32_t cnt_cck_fail;
    uint32_t cnt_ofdm_cca;
    uint32_t cnt_cck_cca;
    uint32_t cnt_ht_crc32_error;
    uint32_t cnt_ht_crc32_ok;
    uint32_t cnt_vht_crc32_error;
    uint32_t cnt_vht_crc32_ok;
    uint32_t cnt_ofdm_crc32_error;
    uint32_t cnt_ofdm_crc32_ok;
    uint32_t cnt_cck_crc32_error;
    uint32_t cnt_cck_crc32_ok;
    uint32_t cnt_all;
    uint32_t cnt_cca_all;
  };
  FaCnt LastFaCnt() const;

private:
  void ThreadLoop();
  /* Port of `phydm_fa_cnt_statistics_ac` (phydm_dig.c:1421). Reads
   * OFDM/CCK FA + CCA + CRC32 counters from page-F BB registers. */
  void ReadFaCountersAc(FaCnt &out);
  /* Port of `phydm_false_alarm_counter_reg_reset` AC branch
   * (phydm_dig.c:1287-1298). Pulses BB reg toggles to clear the
   * counter latches so the next tick captures fresh-since-now
   * counts. */
  void ResetFaCountersAc();
  /* Port of `phydm_dig` (phydm_dig.c:1066) walking BB 0xc50/0xe50/
   * 0x1850/0x1a50 byte 0 (per-path IGI) based on the most recent
   * FA count. Always hits the !is_linked monitor-mode path: bounds
   * [DIG_MIN_COVERAGE=0x1c, DIG_MAX_OF_MIN_BALANCE_MODE=0x2a],
   * step={2,1,2}, FA thresholds={250,500,750}. */
  void DigInit();
  void DigTick(uint32_t fa_cnt);
  void DigWriteIgi(uint8_t igi);
  /* CFO tracking (phydm_cfo_tracking port) — runs each watchdog tick. */
  void CfoTick();
  void SetCrystalCap(uint8_t crystal_cap);

  RtlUsbAdapter _device;
  std::shared_ptr<EepromManager> _eepromManager;
  RadioManagementModule *_radio;
  Logger_t _logger;

  std::thread _thread;
  std::atomic<bool> _running{false};
  std::atomic<bool> _stop{false};

  /* Latest snapshot. mutable so const accessor is feasible without
   * dragging in a mutex; reader sees a torn-but-bounded copy. */
  mutable FaCnt _lastFaCnt{};

  /* DIG state, mirroring `struct phydm_dig_struct` minus the fields
   * we don't use (TDMA, damping check, antdiv override). All in
   * "monitor mode, never linked" semantics — we never look at
   * rssi_min / is_linked because devourer doesn't track them.
   * `_digInitialised` distinguishes the first tick (which reads
   * BB 0xc50 to seed cur_ig_value) from subsequent ticks (which
   * just walk based on FA count). */
  /* Connected-mode link state, pushed from the RX path via
   * SetLinkRssi/SetUnlinked. _s_linked gates monitor vs connected DIG
   * boundaries; _s_rssiDbm carries the live RX RSSI for the floor. */
  static std::atomic<bool> _s_linked;
  static std::atomic<int> _s_rssiDbm;

  /* CFO tracking state. Accumulators are static (fed from the RX thread via
   * AddCfo); the rest is per-watchdog. */
  static std::atomic<int> _s_cfo_sum[2];   /* signed CFO-tail sum, path A/B */
  static std::atomic<unsigned> _s_cfo_cnt[2];
  static std::atomic<unsigned> _s_cfo_pkt; /* total packet count */
  unsigned _cfo_pkt_pre = 0;
  bool _cfo_inited = false;
  bool _cfo_is_adjust = false;
  uint8_t _crystal_cap = 0;
  uint8_t _crystal_cap_def = 0;

  bool _digInitialised = false;
  uint8_t _cur_ig_value = 0x20;
  uint8_t _dm_dig_max = 0x26;       /* DIG_MAX_COVERAGR */
  uint8_t _dm_dig_min = 0x1c;       /* DIG_MIN_COVERAGE */
  uint8_t _dig_max_of_min = 0x2a;   /* DIG_MAX_OF_MIN_BALANCE_MODE */
  uint8_t _rx_gain_range_max = 0x2a;
  uint8_t _rx_gain_range_min = 0x1c;
};

#endif /* PHYDM_WATCHDOG_H */
