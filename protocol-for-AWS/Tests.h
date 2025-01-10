#pragma once
#include "seal/seal.h"
#include "Secret_Sharing.h"
#include "Servers_Protocol.h"
#include "Utility.h"
#include "Constants.h"

#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/gcm.h"
#include "cryptopp/osrng.h"
#include "cryptopp/filters.h"
#include "cryptopp/hkdf.h"


//for zlib:
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

using std::vector;
using std::cout;  using std::endl;
inline int counter = 0; // defines it as global to be edited in multiple files

inline double derive_share = 0; //for testing secret share derive time
inline double share_x_int = 0; //for testing secret share derive time
inline double share_x_frac = 0; //for testing secret share derive time
inline double key_derive = 0; //for testing secret share derive time
inline double gen_init_b_t = 0; //for testing secret share derive time

inline double rec_encode = 0; //for testing rec time
inline double rec_multiply_plain = 0; //for testing rec time
inline double rec_rescale = 0; //for testing rec time




//inline int FLOAT_PRECISTION_FOR_TEST = std::to_string(constants::prime).length(); //12;


namespace tests //class for testing entire protocol and applications in it
{

    int is_correct_secret_sharing(shared_ptr<vector<Ciphertext>> x_final_CT,
        shared_ptr<seal_struct> seal, const vector<double>& x_origin, int input_size, int max_ct_entries);//checks if output of entire protocol is correct batched

    bool is_MAC_HE_valid(shared_ptr<seal_struct> seal_struct, shared_ptr<vector<Ciphertext>> diffCt, int input_size, int max_ct_entries, string mac_type, bool compactMac);

    bool is_MAC_PT_valid(vector<double> diff_vec, int input_size, int max_ct_entries, string mac_type);

    void test_crypto_sink();

    void test_hmac_cryptopp();
};

