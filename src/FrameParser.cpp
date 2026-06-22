#include "FrameParser.h"

#define CONFIG_USB_RX_AGGREGATION 1

#define RXDESC_SIZE 24

#include "basic_types.h"
#include "rtl8812a_recv.h"
#include "PhydmWatchdog.h"

#include <string.h>
#include <vector>
#if 1 /* platform-agnostic: __android_log_print via compat shim on host */
#include <android/log.h>
#endif

struct _phy_status_rpt_8812 {
  /*	DWORD 0*/
  u8 gain_trsw[2];    /*path-A and path-B {TRSW, gain[6:0] }*/
  u8 chl_num_LSB;     /*channel number[7:0]*/
  u8 chl_num_MSB : 2; /*channel number[9:8]*/
  u8 sub_chnl : 4;    /*sub-channel location[3:0]*/
  u8 r_RFMOD : 2;     /*RF mode[1:0]*/

  /*	DWORD 1*/
  u8 pwdb_all;  /*CCK signal quality / OFDM pwdb all*/
  s8 cfosho[2]; /*DW1 byte 1 DW1 byte2	CCK AGC report and CCK_BB_Power /
                   OFDM path-A and path-B short CFO*/
  /*this should be checked again because the definition of 8812 and 8814
   * is different*/
  /*	u8			r_cck_rx_enable_pathc:2;					cck rx enable pathc[1:0]*/
  /*	u8			cck_rx_path:4;							cck rx path[3:0]*/
  u8 resvd_0 : 6;
  u8 bt_RF_ch_MSB : 2; /*8812A:2'b0			8814A: bt rf channel keep[7:6]*/
  u8 ant_div_sw_a : 1; /*8812A: ant_div_sw_a    8814A: 1'b0*/
  u8 ant_div_sw_b : 1; /*8812A: ant_div_sw_b    8814A: 1'b0*/
  u8 bt_RF_ch_LSB : 6; /*8812A: 6'b0                   8814A: bt rf
                          channel keep[5:0]*/
  s8 cfotail[2];       /*DW2 byte 1 DW2 byte 2	path-A and path-B CFO tail*/
  u8 PCTS_MSK_RPT_0;   /*PCTS mask report[7:0]*/
  u8 PCTS_MSK_RPT_1;   /*PCTS mask report[15:8]*/

  /*	DWORD 3*/
  s8 rxevm[2]; /*DW3 byte 1 DW3 byte 2	stream 1 and stream 2 RX EVM*/
  s8 rxsnr[2]; /*DW3 byte 3 DW4 byte 0	path-A and path-B RX SNR*/

  /*	DWORD 4*/
  u8 PCTS_MSK_RPT_2;     /*PCTS mask report[23:16]*/
  u8 PCTS_MSK_RPT_3 : 6; /*PCTS mask report[29:24]*/
  u8 pcts_rpt_valid : 1; /*pcts_rpt_valid*/
  u8 resvd_1 : 1;        /*1'b0*/
  s8 rxevm_cd[2];        /*DW 4 byte 3 DW5 byte 0  8812A: 16'b0	8814A: stream 3
                            and stream 4 RX EVM*/

  /*	DWORD 5*/
  u8 csi_current[2];  /*DW5 byte 1 DW5 byte 2	8812A: stream 1 and 2 CSI
                         8814A:  path-C and path-D RX SNR*/
  u8 gain_trsw_cd[2]; /*DW5 byte 3 DW6 byte 0	path-C and path-D {TRSW,
                         gain[6:0] }*/

  /*	DWORD 6*/
  s8 sigevm;             /*signal field EVM*/
  u8 antidx_antc : 3;    /*8812A: 3'b0		8814A: antidx_antc[2:0]*/
  u8 antidx_antd : 3;    /*8812A: 3'b0		8814A: antidx_antd[2:0]*/
  u8 dpdt_ctrl_keep : 1; /*8812A: 1'b0		8814A: dpdt_ctrl_keep*/
  u8 GNT_BT_keep : 1;    /*8812A: 1'b0		8814A: GNT_BT_keep*/
  u8 antidx_anta : 3;    /*antidx_anta[2:0]*/
  u8 antidx_antb : 3;    /*antidx_antb[2:0]*/
  u8 hw_antsw_occur : 2; /*1'b0*/
};

FrameParser::FrameParser(Logger_t logger) : _logger{logger} {}

static rx_pkt_attrib rtl8812_query_rx_desc_status(uint8_t *pdesc) {
  auto pattrib = rx_pkt_attrib{};

  /* Offset 0 */
  pattrib.pkt_len = GET_RX_STATUS_DESC_PKT_LEN_8812(pdesc);
  pattrib.crc_err = GET_RX_STATUS_DESC_CRC32_8812(pdesc);
  pattrib.icv_err = GET_RX_STATUS_DESC_ICV_8812(pdesc);
  pattrib.drvinfo_sz =
      (uint8_t)(GET_RX_STATUS_DESC_DRVINFO_SIZE_8812(pdesc) * 8);
  pattrib.encrypt = GET_RX_STATUS_DESC_SECURITY_8812(pdesc);
  pattrib.qos = GET_RX_STATUS_DESC_QOS_8812(pdesc);
  /* Qos data, wireless
                                                          lan header length is
                                                          26 */
  pattrib.shift_sz = GET_RX_STATUS_DESC_SHIFT_8812(
      pdesc); /* ((le32_to_cpu(pdesc.rxdw0) >> 24) & 0x3); */
  pattrib.physt = GET_RX_STATUS_DESC_PHY_STATUS_8812(
      pdesc); /* ((le32_to_cpu(pdesc.rxdw0) >> 26) & 0x1); */
  pattrib.bdecrypted = !GET_RX_STATUS_DESC_SWDEC_8812(
      pdesc); /* (le32_to_cpu(pdesc.rxdw0) & BIT(27))? 0:1; */

  /* Offset 4 */
  pattrib.priority = GET_RX_STATUS_DESC_TID_8812(pdesc);
  pattrib.mdata = GET_RX_STATUS_DESC_MORE_DATA_8812(pdesc);
  pattrib.mfrag = GET_RX_STATUS_DESC_MORE_FRAG_8812(pdesc);
  /* more fragment bit */

  /* Offset 8 */
  pattrib.seq_num = GET_RX_STATUS_DESC_SEQ_8812(pdesc);
  pattrib.frag_num = GET_RX_STATUS_DESC_FRAG_8812(pdesc);
  /* fragmentation number */

  if (GET_RX_STATUS_DESC_RPT_SEL_8812(pdesc)) {
    pattrib.pkt_rpt_type = RX_PACKET_TYPE::C2H_PACKET;
  } else {
    pattrib.pkt_rpt_type = RX_PACKET_TYPE::NORMAL_RX;
  }

  /* Offset 12 */
  pattrib.data_rate = GET_RX_STATUS_DESC_RX_RATE_8812(pdesc);
  /* Offset 16 */
  pattrib.sgi = GET_RX_STATUS_DESC_SPLCP_8812(pdesc);
  pattrib.ldpc = GET_RX_STATUS_DESC_LDPC_8812(pdesc);
  pattrib.stbc = GET_RX_STATUS_DESC_STBC_8812(pdesc);
  pattrib.bw = GET_RX_STATUS_DESC_BW_8812(pdesc);

  /* Offset 20 */
  /* pattrib.tsfl=(byte)GET_RX_STATUS_DESC_TSFL_8812(pdesc); */

  return pattrib;
}

__inline static u32 _RND8(u32 sz) {
  u32 val;

  val = ((sz >> 3) + ((sz & 7) ? 1 : 0)) << 3;

  return val;
}

std::vector<Packet> FrameParser::recvbuf2recvframe(std::span<uint8_t> ptr) {
  auto pbuf = ptr;
  auto pkt_cnt = GET_RX_STATUS_DESC_USB_AGG_PKTNUM_8812(pbuf.data());
#if 1 /* platform-agnostic: __android_log_print via compat shim on host */
  // A-MPDU diagnostic: log aggregate size distribution every 500 URBs.
  // If pkt_cnt is mostly 1-2, the AP sends single frames (no A-MPDU).
  // If pkt_cnt is 5+, A-MPDU IS being used and frames are being lost downstream.
  { static int urbN=0, totalSub=0; urbN++; (void)totalSub;
    // Log at end of function where ret.size() is known
    }
#endif

  auto ret = std::vector<Packet>{};

  do {
    auto pattrib = rtl8812_query_rx_desc_status(pbuf.data());

    // NOTE: CRC/ICV-bad frames are skipped PER-FRAME below — NOT break'd. The chip packs
    // many 802.11 MPDUs into one bulk-IN transfer (USB_AGG_PKTNUM); break'ing on the first
    // bad frame discarded it AND every good frame packed after it in the same transfer ->
    // partial video frames / tearing, worse at higher rate (more MPDUs per aggregate).
    auto pkt_offset = RXDESC_SIZE + pattrib.drvinfo_sz + pattrib.shift_sz +
                      pattrib.pkt_len; // this is offset for next package

    if ((pattrib.pkt_len <= 0) || (pkt_offset > pbuf.size())) {
      _logger->warn(
          "RX Warning!,pkt_len <= 0 or pkt_offset > transfer_len; pkt_len: "
          "{}, pkt_offset: {}, transfer_len: {}",
          pattrib.pkt_len, pkt_offset, pbuf.size());
      break;
    }

    if (pattrib.mfrag) {
      // !!! We skips this packages because ohd not use fragmentation
      _logger->warn("mfrag scipping");

      // if (rtw_os_alloc_recvframe(precvframe, pbuf.Slice(pattrib.shift_sz +
      // pattrib.drvinfo_sz + RXDESC_SIZE), pskb) == false)
      //{
      //     return false;
      // }
    }

    // recvframe_put(precvframe, pattrib.pkt_len);
    /* recvframe_pull(precvframe, drvinfo_sz + RXDESC_SIZE); */

#if 1 /* platform-agnostic: __android_log_print via compat shim on host */
    // DIAG: count CRC/ICV-bad vs good frames. If crc is a large fraction, the AP's
    // chosen MCS is too high for the link (antenna/MIMO/SNR) -> most frames dropped
    // -> low goodput despite a high rxrate. Logged every 2000 frames.
    { static int g=0,b=0; if (pattrib.crc_err||pattrib.icv_err) b++; else g++;
      if (((g+b)%2000)==0) __android_log_print(4,"rxd-crc","good=%d crcbad=%d (%d%% bad)",g,b,(b*100)/(g+b)); }
    // DIAG: AP's chosen TX rate/bandwidth to us. data_rate = DESC_RATE idx (VHT 1SS MCS0=44,
    // 2SS MCS0-9=54-63), bw = 0/1/2 (20/40/80 MHz). This is the direct readout of whether the
    // HW-BlockAck fix made the AP's rate-control climb. Histogram every 2000 good frames.
    { static int n=0, maxrate=0, bwhi=0, bw80=0, aggFrames=0; static unsigned long bytes=0;
      static long snrSumA=0, snrSumB=0; static int snrN=0;
      if (!(pattrib.crc_err||pattrib.icv_err)) {
        n++; bytes += pattrib.pkt_len;
        if (pattrib.data_rate > maxrate) maxrate = pattrib.data_rate;
        if (pattrib.bw > bwhi) bwhi = pattrib.bw;
        if (pattrib.bw == 2) bw80++;
        // PAGGR (desc bit15) = this frame was part of an A-MPDU. If aggFrames stays LOW the AP
        // sends single MPDUs (per-frame ACK) → throughput capped regardless of bandwidth; if HIGH
        // the AP IS aggregating and the cap is elsewhere. This is the built-in "sniffer".
        if (GET_RX_STATUS_DESC_PAGGR_8812(pbuf.data())) aggFrames++;
        // RX SNR per path (phystatus rxsnr, dB/2). Marginal SNR at MCS8 -> PER; clean SNR -> the
        // 5-6% retry / 2x gap is NOT reception (front-end PHYDM won't help, it's aggregation).
        if (pattrib.physt) {
          const struct _phy_status_rpt_8812* ps =
              reinterpret_cast<const struct _phy_status_rpt_8812*>(pbuf.data() + RXDESC_SIZE);
          snrSumA += ps->rxsnr[0]; snrSumB += ps->rxsnr[1]; snrN++;
        }
        if ((n%2000)==0) {
          __android_log_print(4,"rxd-rate","last rate=%d bw=%d | maxrate=%d maxbw=%d bw80=%d/2000 ampduFrames=%d/2000 bytes=%lu | SNR_A=%lddB SNR_B=%lddB",
              (int)pattrib.data_rate,(int)pattrib.bw,maxrate,bwhi,bw80,aggFrames,bytes,
              snrN?(snrSumA/snrN)/2:0, snrN?(snrSumB/snrN)/2:0);
          maxrate=0; bwhi=0; bw80=0; aggFrames=0; bytes=0; snrSumA=0; snrSumB=0; snrN=0;
        }
      } }
    // BA-EFFICIENCY DIAG: the decisive test for the paced-throughput ceiling. For each good QoS
    // DATA frame, read the 802.11 Retry bit (FC bit 11) and track per-TID sequence gaps/dups.
    //   * HIGH retry% + LOW crc%  => the AP is RE-transmitting frames we already received cleanly
    //                                => our HW BlockAck bitmap isn't ACKing them => A-MPDU efficiency
    //                                collapses => the ~17Mbps paced ceiling. (the BA-bitmap bug)
    //   * seqGaps/missedSeqs       => genuine over-air loss (frames the AP sent never arrived).
    //   * dups                     => we received a retransmit of a seq we already had.
    { static int total=0, retried=0, gaps=0, missed=0, dups=0, inorder=0;
      static int lastSeq[16]; static bool seqInit[16];
      if (!(pattrib.crc_err||pattrib.icv_err) && pattrib.qos) {
        size_t fcOff = pattrib.shift_sz + pattrib.drvinfo_sz + RXDESC_SIZE;
        bool retry = (fcOff + 1 < pbuf.size()) && (pbuf[fcOff+1] & 0x08);
        int tid = pattrib.priority & 0x0f;
        int s   = pattrib.seq_num & 0xfff;
        total++; if (retry) retried++;
        // One-shot raw sample: dump 24 consecutive QoS frames so the seq pattern is visible
        // (validates whether the seq field is monotonic and the retry/tid reads are sane).
        { static int raw=0; if (raw < 24) { raw++;
            __android_log_print(4,"rxd-ba-raw","#%d tid=%d seq=%d retry=%d fc=%02x%02x rate=%d bw=%d len=%d",
              raw, tid, s, (int)retry,
              (fcOff<pbuf.size())?pbuf[fcOff]:0, (fcOff+1<pbuf.size())?pbuf[fcOff+1]:0,
              (int)pattrib.data_rate, (int)pattrib.bw, (int)pattrib.pkt_len); } }
        if (!seqInit[tid]) { seqInit[tid]=true; lastSeq[tid]=s; }
        else {
          int fwd = (s - lastSeq[tid]) & 0xfff;            // forward distance mod 4096
          if (fwd == 1) inorder++;                          // in-order, no loss
          else if (fwd >= 2 && fwd < 2048) { gaps++; missed += (fwd-1); lastSeq[tid]=s; } // gap = missing
          else dups++;                                      // fwd==0 or backward => retransmit/dup
          if (fwd >= 1 && fwd < 2048) lastSeq[tid]=s;        // advance only on forward progress
        }
        if ((total%2000)==0) {
          __android_log_print(4,"rxd-ba",
            "QoS=%d inorder=%d retryBit=%d(%d%%) seqGaps=%d missedSeqs=%d dups=%d",
            total, inorder, retried, (retried*100)/total, gaps, missed, dups);
          total=retried=gaps=missed=dups=inorder=0;
          for (int i=0;i<16;i++) seqInit[i]=false;
        }
      } }
#endif
    if (pattrib.crc_err || pattrib.icv_err) {
      // Bad frame: skip ITS payload but keep walking the aggregate (do not break).
    } else if (pattrib.pkt_rpt_type ==
        RX_PACKET_TYPE::NORMAL_RX) /* Normal rx packet */
    {
      ret.push_back({pattrib, pbuf.subspan(pattrib.shift_sz +
                                               pattrib.drvinfo_sz + RXDESC_SIZE,
                                           pattrib.pkt_len)});

      struct _phy_status_rpt_8812 driver_data;
      memcpy(static_cast<void*>(&driver_data), pbuf.data() + RXDESC_SIZE, sizeof(driver_data));
      ret.back().RxAtrib.rssi[0] = driver_data.gain_trsw[0];
      ret.back().RxAtrib.rssi[1] = driver_data.gain_trsw[1];
      /* 8814AU path C/D RSSI lives in gain_trsw_cd; on 8812/8811 these bytes
       * are 0. */
      ret.back().RxAtrib.rssi[2] = driver_data.gain_trsw_cd[0];
      ret.back().RxAtrib.rssi[3] = driver_data.gain_trsw_cd[1];
      ret.back().RxAtrib.snr[0] = driver_data.rxsnr[0];
      ret.back().RxAtrib.snr[1] = driver_data.rxsnr[1];
      /* 8814AU path C/D SNR is in csi_current per upstream's struct comment
       * (DWORD 5 byte 1-2); on 8812 those bytes hold stream 1/2 CSI which we
       * don't surface, so the value is meaningful only when the chip is
       * 8814AU. */
      ret.back().RxAtrib.snr[2] = static_cast<int8_t>(driver_data.csi_current[0]);
      ret.back().RxAtrib.snr[3] = static_cast<int8_t>(driver_data.csi_current[1]);
      /* CFO-tracking feed (phydm_cfo_tracking): only OFDM/HT/VHT (data_rate>=4;
       * CCK reuses these phystatus bytes for AGC). The watchdog averages the
       * path-A/B CFO tail and steps the crystal cap to null the carrier-freq
       * offset — cuts the dense-MCS8 RX PER that makes the AP throttle our A-MPDU. */
      if (pattrib.physt && pattrib.data_rate >= 4) {
        PhydmWatchdog::AddCfo(driver_data.cfotail[0], driver_data.cfotail[1]);
      }
    } else {
      /* pkt_rpt_type == TX_REPORT1-CCX, TX_REPORT2-TX RTP,HIS_REPORT-USB HISR
       * RTP */
      if (pattrib.pkt_rpt_type == RX_PACKET_TYPE::C2H_PACKET) {
        _logger->info("RX USB C2H_PACKET");
        // rtw_hal_c2h_pkt_pre_hdl(padapter, precvframe.u.hdr.rx_data,
        // pattrib.pkt_len);
      } else if (pattrib.pkt_rpt_type == RX_PACKET_TYPE::HIS_REPORT) {
        _logger->info("RX USB HIS_REPORT");
      }
    }

    /* jaguar 8-byte alignment */
    pkt_offset = (uint16_t)_RND8(pkt_offset);
    // pkt_cnt--;

    if (pkt_offset >= pbuf.size()) {
      break;
    }
    pbuf = pbuf.subspan(pkt_offset, pbuf.size() - pkt_offset);
  } while (pbuf.size() > 0);

  if (pkt_cnt != 0) {
    _logger->info("Unprocessed packets: {}", pkt_cnt);
  }
#if 1 /* platform-agnostic: __android_log_print via compat shim on host */
  { static int urbN=0, totalFrames=0; urbN++; totalFrames += (int)ret.size();
    if ((urbN % 250) == 0) {
      __android_log_print(4,"rxd-agg",
        "URB#%d pkts=%zu avg=%.1f pkt_cnt=%u",
        urbN, ret.size(), (float)totalFrames/(float)urbN, (unsigned)pkt_cnt);
      totalFrames = 0;
    } }
#endif

  return ret;
}

void rtl8812a_cal_txdesc_chksum(uint8_t *ptxdesc) {
  u16 *usPtr;
  u32 count;
  u32 index;
  u16 checksum = 0;

  usPtr = (u16 *)ptxdesc;

  /* checksum is always calculated by first 32 bytes, */
  /* and it doesn't depend on TX DESC length. */
  /* Thomas,Lucas@SD4,20130515 */
  count = 16;

  /* Clear first */
  SET_TX_DESC_TX_DESC_CHECKSUM_8812(ptxdesc, 0);

  for (index = 0; index < count; index++)
    checksum = checksum ^ le16_to_cpu(*(usPtr + index));

  SET_TX_DESC_TX_DESC_CHECKSUM_8812(ptxdesc, checksum);
}

int rtw_action_frame_parse(const u8 *frame, u32 frame_len, u8 *category,
                           u8 *action) {
  /*const u8 *frame_body = frame + sizeof(struct rtw_ieee80211_hdr_3addr);
  u16 fc;
  u8 c;
  u8 a = ACT_PUBLIC_MAX;

  fc = le16_to_cpu(((struct rtw_ieee80211_hdr_3addr *)frame)->frame_ctl);

  if ((fc & (RTW_IEEE80211_FCTL_FTYPE | RTW_IEEE80211_FCTL_STYPE))
      != (RTW_IEEE80211_FTYPE_MGMT | RTW_IEEE80211_STYPE_ACTION)
     )
          return _FALSE;

  c = frame_body[0];

  switch (c) {
  case RTW_WLAN_CATEGORY_P2P: // vendor-specific
          break;
  default:
          a = frame_body[1];
  }

  if (category)
          *category = c;
  if (action)
          *action = a;
*/
  return _TRUE;
}
