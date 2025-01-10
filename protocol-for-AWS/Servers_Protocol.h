#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include "Utility.h"
#include "Tests.h"
#include "Secret_Sharing.h"
#include "MAC.h"

using namespace utility;

inline const char* CIPHERTEXTS_BT_T_DIR {"ciphertexts_b_t"};
inline const char* CIPHERTEXTS_X_INT_FRAC_DIR {"ciphertexts_x_int_frac"};

inline const char* TAGS_SQ_DIR {"tags_sq"};
inline const char* TAGS_SR_DIR {"tags_sr"};

inline bool use_batch_for_aes {true};

namespace awsparams {
    //inline const char *bucket_name = "asec-tests";
    //inline const char *region = "us-west-2";
	inline const char *bucket_name = "secret-share-bucket";
    inline const char *region = "eu-central-1";
}
using std::shared_ptr; using std::make_shared; using std::string;

class Servers_Protocol //class for protocol server functions
{

public:
	Servers_Protocol() {}

	shared_ptr<vector<Ciphertext>> DS(const shared_ptr<vector<Ciphertext>> x_int_FHE, const shared_ptr<vector<Ciphertext>> x_frac_FHE, shared_ptr<seal_struct> seal);

    shared_ptr<seal_struct> gen_seal_params(int poly_modulus_degree, vector<int> bit_sizes, double scale); //creates context, keygen, evaluator
    shared_ptr<seal_struct> gen_seal_params(int poly_modulus_degree, vector<seal::Modulus> coeff_modulus, double scale); //creates context, keygen, evaluator
		//encoder, public key - all seal struct parameters

};

