#pragma once
#include "seal/seal.h"
#include "../Servers_Protocol.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <vector>

//includes for openssl hkdf
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

/*
//includes for hkdf cryptopp
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <iostream>
*/


#define MAX_FILE_NAME 256
using std::cout;  using std::endl;
using std::string;


class TP_performance_metrics
{
public:
    long long encode = 0;
    long long encrypt = 0;
    long long serialize = 0;
    long long store = 0;
    long long load = 0;
    long long deserialize = 0;
    long long hmac = 0;
    long long verify = 0;

    long long encode_no_mac = 0;
    long long encrypt_no_mac = 0;
    long long serialize_no_mac = 0;
    long long store_no_mac = 0;
    long long load_no_mac = 0;
    long long deserialize_no_mac = 0;
    long long decode_no_mac = 0;
    long long decrypt_no_mac = 0;

    long long hkdf = 0;

    static std::string getHeader();
};

std::ostream& operator<<(std::ostream&, const TP_performance_metrics& tpPerformanceMetrics);

class Test_Protocol
{
private:
    vector<double> _secret_num_vec;
    enc_init_params_s _enc_init_params;
public:
    Test_Protocol(string enc_params_file); // constructor
    ~Test_Protocol() {} //class d'tor
    Test_Protocol(const Test_Protocol& test_protocol) {} //copy c'tor

    shared_ptr<seal_struct> set_seal_struct(); //generate seal struct from params file that's in class

    void test_save_time(void);

    //storage test no hmac
    void test_storage_fhe(ullong input_size, shared_ptr<seal_struct> seal, TP_performance_metrics& performanceMetrics);

    //storage batched test with hmac
    void hmac_on_FHE(ullong input_size, shared_ptr<seal_struct> seal, TP_performance_metrics& performanceMetrics);
    void test_storage_cleartext(ullong input_size);

    void test_storage_batched_sim();
    //storage test without timing for unbatched data, with and without mac tag
    void test_storage_unbatched(ullong input_size, shared_ptr<seal_struct> seal, bool with_mac, TP_performance_metrics& performanceMetrics);

    //test compact mac functions
    void shift_data_range(ullong input_size);
    int test_compact_HE_mac_optimized(ullong input_size);// test compact optimize batched MAC and HE verify
    int test_compact_unbatched_HE_mac(ullong input_size); //test compact unbatched MAC and HE verify

    //local compact unbatched verify HE for tests, MAC.cpp version requires DS performance metrics.
    const Ciphertext& compact_unbatched_VerifyHE(const shared_ptr<seal_struct> seal_struct , K_MAC kmac, Ciphertext& x_int,
        Ciphertext& x_frac, mac_tag_ct& tag_he, bool squareDiff, int len);


    Ciphertext verifyHE_batched_y(const shared_ptr<seal_struct> seal_struct , K_MAC_Batched kmac, Ciphertext ct_x_int, Ciphertext ct_x_frac);
    Ciphertext verifyHE_batched_y_tag(const shared_ptr<seal_struct> seal_struct , int len_vec, K_MAC_Batched kmac, Ciphertext ct_tr, Ciphertext ct_alpha_int, Ciphertext ct_beta_int);

    void test_hkdf(TP_performance_metrics& performanceMetrics);
    void test_crypto_sink_hmac(TP_performance_metrics& performanceMetrics);

    int test_openssl_hkdf(bool is_sha512, TP_performance_metrics& performanceMetrics);

};

