#pragma once
#include "seal/seal.h"
#include "seal/evaluator.h" // for basic operation on FHE data
#include <iomanip>
#include <fstream>
#include <iostream>
#include "seal/util/polyarithsmallmod.h"
#include <chrono>
#include "Constants.h"
#include "Utility.h"
#include "K_MAC.h"
#include <string>

//for cryptopp
#include "cryptopp/cryptlib.h"
#include "cryptopp/files.h"
#include "cryptopp/hex.h"
#include "cryptopp/sha.h"
#include "cryptopp/hmac.h"
using namespace CryptoPP;



using namespace seal;
using namespace utility;

using std::tuple; using std::make_tuple;

using std::vector;
using std::cout; using std::endl; using std::pow;
using std::chrono::nanoseconds;

using std::unique_ptr; using std::make_unique;
using std::shared_ptr; using std::make_shared;


struct sharePT //struct for share algorithm output
{
	ullong t;
	int  b;
	double x_int;
	double x_frac;
	double x_int_plus_x_frac;
} typedef sharePT_struct;

struct seal_struct //struct for all seal's initialization for HE, setup in servers protocol
{
	SEALContext context_ptr;//seal context is already type ptr
	shared_ptr<Evaluator> evaluator_ptr;
	shared_ptr<CKKSEncoder> encoder_ptr;
	shared_ptr<KeyGenerator> keygen_ptr;
	shared_ptr<Encryptor> encryptor_ptr;
	shared_ptr<Decryptor> decryptor_ptr;
	shared_ptr<seal::PublicKey> pk_ptr;
	shared_ptr<SecretKey> sk_ptr;

    shared_ptr<RelinKeys> relink_ptr;
	int poly_modulus_degree;
	vector<int> bit_sizes;
	double scale;
} typedef seal_struct;

class Secret_Sharing { //class for secret sharing operations

private:
    enc_init_params_s _enc_init_params;
    std::vector<byte> _keys;

public:
	Secret_Sharing(enc_init_params_s _enc_inite_params);

	//secret sharing for PT - hkdf version
    sharePT_struct Derive_b_t(SHARE_MAC_KEYS *keys, int prime_bits_to_bytes);

    //secret sharing for PT - hmac version
    sharePT_struct Derive_b_t(CryptoPP::HMAC<CryptoPP::SHA256> hmac, int index);
    nanoseconds Share(vector<double> secret_num_vec, CryptoPP::HMAC<CryptoPP::SHA256> hmac, ullong num_of_secrets, std::ostringstream *os);

    sharePT_struct gen_share(ullong x, SHARE_MAC_KEYS *secret_share_keys, int prime_bits_to_bytes);
    double Rec_PT(double b_plus_t, int x_int, double x_frac);

    const Ciphertext& Rec_CT(const vector<double>& cleartext_vec, const vector<double>& cleartext_for_cipher_vec, Ciphertext& x_int_FHE, Ciphertext& x_frac_FHE, const shared_ptr<seal_struct> context);

};
