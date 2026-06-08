// ============================================================================
//  Wpa2Crypto.cpp — WPA2 crypto backend, now BACKED BY VENDORED PRIMITIVES
//  (src/crypto/Sha1Hmac + AesCcm). No external deps; builds on NDK/Linux.
//  Fills the Crypto vtable Wpa2Supplicant consumes.
// ============================================================================
#include "Wpa2Crypto.h"
#include "crypto/Sha1Hmac.h"
#include "crypto/AesCcm.h"
#include <cstring>

namespace apfpv {

static std::array<uint8_t,32> pbkdf2_pmk_impl(const std::string& pass,const uint8_t* ssid,size_t sl){
    std::array<uint8_t,32> pmk{};
    crypto::pbkdf2_sha1(pass.c_str(), ssid, sl, 4096, pmk.data(), 32);
    return pmk;
}

// IEEE 802.11i PRF: R = HMAC-SHA1(K, label||0x00||data||i) concatenated.
static std::vector<uint8_t> prf_impl(const uint8_t* key,size_t kl,const std::string& label,
                                     const uint8_t* data,size_t dl,size_t outLen){
    std::vector<uint8_t> out; out.reserve(((outLen+19)/20)*20);
    for(uint8_t i=0; out.size()<outLen; ++i){
        std::vector<uint8_t> buf(label.begin(),label.end());
        buf.push_back(0x00); buf.insert(buf.end(),data,data+dl); buf.push_back(i);
        uint8_t mac[20]; crypto::hmac_sha1(key,kl,buf.data(),buf.size(),mac);
        out.insert(out.end(),mac,mac+20);
    }
    out.resize(outLen); return out;
}

static std::array<uint8_t,16> eapol_mic_impl(const uint8_t* kck,const uint8_t* msg,size_t len){
    uint8_t full[20]; crypto::hmac_sha1(kck,16,msg,len,full);
    std::array<uint8_t,16> mic{}; std::memcpy(mic.data(),full,16); return mic;  // AES/SHA1 -> first 16
}

static bool ccmp_decrypt_impl(const uint8_t* tk,const uint8_t* nonce,const uint8_t* in,size_t inLen,
                              const uint8_t* aad,size_t aadLen,std::vector<uint8_t>& out){
    out.resize(inLen>8?inLen-8:0);
    return crypto::aes_ccm_decrypt(tk,nonce,13,aad,aadLen,in,inLen,out.data());
}
static std::vector<uint8_t> ccmp_encrypt_impl(const uint8_t* tk,const uint8_t* nonce,const uint8_t* in,
                              size_t inLen,const uint8_t* aad,size_t aadLen){
    std::vector<uint8_t> out(inLen+8);
    crypto::aes_ccm_encrypt(tk,nonce,13,aad,aadLen,in,inLen,out.data());
    return out;
}

Crypto MakeWpa2Crypto(){
    Crypto c;
    c.pbkdf2_pmk   = [](const std::string& p,const uint8_t* s,size_t n){ return pbkdf2_pmk_impl(p,s,n); };
    c.prf          = [](const uint8_t* k,size_t kl,const std::string& l,const uint8_t* d,size_t dl,size_t o){ return prf_impl(k,kl,l,d,dl,o); };
    c.eapol_mic    = [](const uint8_t* k,const uint8_t* m,size_t l){ return eapol_mic_impl(k,m,l); };
    c.ccmp_decrypt = [](const uint8_t* tk,const uint8_t* n,const uint8_t* in,size_t il,const uint8_t* a,size_t al,std::vector<uint8_t>& o){ return ccmp_decrypt_impl(tk,n,in,il,a,al,o); };
    c.ccmp_encrypt = [](const uint8_t* tk,const uint8_t* n,const uint8_t* in,size_t il,const uint8_t* a,size_t al){ return ccmp_encrypt_impl(tk,n,in,il,a,al); };
    return c;
}

} // namespace apfpv
