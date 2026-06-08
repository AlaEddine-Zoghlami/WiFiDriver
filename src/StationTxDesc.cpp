// ============================================================================
//  StationTxDesc.cpp — unicast station TX descriptor (impl)
//  KEY FIX vs devourer monitor path: BMC=0 (unicast, enables ACK handshake).
//  Reuses devourer's working HWSEQ/retry/rate/checksum machinery.
//  Declarations in StationTxDesc.h.
// ============================================================================
#include "basic_types.h"
#include "FrameParser.h"
#include "StationTxDesc.h"

namespace apfpv {

void FillStationTxDesc(uint8_t* txdesc, uint16_t payloadLen, uint8_t descOffset,
                       uint8_t macId, StationFrameKind kind, uint8_t rateId, uint8_t txRate) {
    SET_TX_DESC_PKT_SIZE_8812(txdesc, payloadLen);
    SET_TX_DESC_OFFSET_8812(txdesc, descOffset);
    SET_TX_DESC_FIRST_SEG_8812(txdesc, 1);
    SET_TX_DESC_LAST_SEG_8812(txdesc, 1);
    SET_TX_DESC_OWN_8812(txdesc, 1);
    // Broadcast mgmt (beacon) must set BMC=1 so the chip does NOT wait for an ACK
    // and retry — otherwise the frame never radiates. Unicast station frames keep
    // BMC=0 (the ACK-handshake fix).
    bool bmc = (kind == StationFrameKind::BroadcastMgmt);
    SET_TX_DESC_BMC_8812(txdesc, bmc ? 1 : 0);
    SET_TX_DESC_MACID_8812(txdesc, macId);
    SET_TX_DESC_QUEUE_SEL_8812(txdesc,
        (kind == StationFrameKind::Mgmt || kind == StationFrameKind::BroadcastMgmt) ? 0x12 : 0x00);
    SET_TX_DESC_SEC_TYPE_8812(txdesc, 0);            // SW-CCMP / cleartext mgmt
    SET_TX_DESC_HWSEQ_EN_8812(txdesc, 1);
    SET_TX_DESC_RATE_ID_8812(txdesc, rateId);
    SET_TX_DESC_USE_RATE_8812(txdesc, 1);
    SET_TX_DESC_TX_RATE_8812(txdesc, txRate);
    SET_TX_DESC_RETRY_LIMIT_ENABLE_8812(txdesc, bmc ? 0 : 1);   // no retry for broadcast
    SET_TX_DESC_DATA_RETRY_LIMIT_8812(txdesc, bmc ? 0 : 12);
    rtl8812a_cal_txdesc_chksum(txdesc);
}

} // namespace apfpv
