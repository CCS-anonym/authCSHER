//class for MAC over cleartext and ciphertext
#pragma once
#include <iostream>
#include <vector>
#include <math.h>
#include "Constants.h"
#include "Utility.h"
#include "Secret_Sharing.h"
#include "K_MAC.h"
#include "Destination_Server/DS_Performance_metrics.h"

using std::shared_ptr, std::make_shared;
using namespace utility;

struct single_key_mac {
	double a;
	double b;
	double c;
	double d;
};

struct single_mac_tag {
	double z_qmskd;
	double z_r;
	double y_r;
};

struct key_mac {
	shared_ptr<vector<double>> a;
	shared_ptr<vector<double>> b;
	shared_ptr<vector<double>> c;
	shared_ptr<vector<double>> d;
} typedef key_mac;


//HE STRUCTS
struct mac_tag_ct {
	shared_ptr<Ciphertext> z_qmskd_ct;
	shared_ptr<Ciphertext> t_r_ct;
}typedef mac_tag_ct;


//structs for new scheme

struct mac_tag_batched_optimized
{
    vector<double> mac_part1;
    vector<unsigned char> mac_part2;


};

struct mac_tag_batched_ct { //optimized batched tag
	shared_ptr<Ciphertext> y_alpha_int_ct;
	shared_ptr<Ciphertext> y_beta_int_ct;
	shared_ptr<Ciphertext> y_t_ct;
}typedef mac_tag_batched_ct;

struct single_compact_mac_tag {
	double y_r;
	double y_alpha_int;
	double y_alpha_frac;
	double y_beta_int;
	double y_beta_frac;
} typedef single_compact_mac_tag;


struct compact_mac_tag {
	shared_ptr<vector<double>> y_r;
	shared_ptr<vector<double>> y_alpha_int;
	shared_ptr<vector<double>> y_alpha_frac;
	shared_ptr<vector<double>> y_beta_int;
	shared_ptr<vector<double>> y_beta_frac;
}typedef compact_mac_tag;


struct compact_unbatched_mac_tag {
	shared_ptr<vector<double>> y_r;
	shared_ptr<vector<double>> y_alpha_int;
	shared_ptr<vector<double>> y_alpha_frac;
}typedef compact_unbatched_mac_tag;



class MAC {
private:
    enc_init_params_s _enc_init_params;

    // for batched mac accumulation
    vector<Ciphertext> a_int_times_x_int;
    vector<Ciphertext> a_frac_times_x_frac;

public:
	MAC(enc_init_params_s enc_init_params);
	~MAC() {}//class d'tor
	MAC(const MAC& mac) {}//copy c'tor

	//single entry mac functions
	single_key_mac Derive_kmac_single(CryptoPP::HMAC<SHA256> hmac, int index); //deriving key with crypto++ hmac
	single_mac_tag mac_single(single_key_mac kmac, double x);
	bool verify_single(single_key_mac kmac, double x, single_mac_tag mac);

	key_mac Derive_kmac(const char* dp_cs_key, int len);

	//HE functions
	const Ciphertext& verifyHE(const shared_ptr<seal_struct> seal_struct , const key_mac& kmac, Ciphertext& x,mac_tag_ct& tag_he, bool squareDiff, int len, DS_performance_metrics* performanceMetrics);

    //mult ct by pt inplace with rescale and set scale
	Ciphertext& mult_ct_pt_inplace(const shared_ptr<seal_struct> seal_struct, Ciphertext& ct, const Plaintext& pt);

	//compact k-mac functions
    K_MAC_Batched Derive_compact_kmac_single(CryptoPP::HMAC<SHA256>& hmac, ullong start_index, ullong amount);
    K_MAC Derive_compact_kmac_unbatched_single(CryptoPP::HMAC<SHA256>& hmac, ullong start_index, ullong amount);

    //batched MAC functions
    mac_tag_batched_optimized compact_mac_batched_optimized(K_MAC_Batched kmac, vector<double> y_vec);

    compact_mac_tag compact_mac(vector<K_MAC_Batched>& kmac_vec, vector<vector<double>>& x_int, vector<vector<double>>& x_frac, ullong input_size);

    //verify for batched split into two parts, computing y, y_tag then subtracting to check difference is 0.
    Ciphertext verifyHE_batched_y(const shared_ptr<seal_struct> seal_struct , K_MAC_Batched kmac, Ciphertext ct_x_int, Ciphertext ct_x_frac, DS_performance_metrics* performanceMetrics);
    Ciphertext verifyHE_batched_y_tag(const shared_ptr<seal_struct> seal_struct , int len_vec, K_MAC_Batched kmac, Ciphertext ct_tr, Ciphertext ct_alpha_int, Ciphertext ct_beta_int, DS_performance_metrics* performanceMetrics);


    //unbatched MAC functions:
	single_mac_tag single_compact_mac(K_MAC kmac, int index, double x_int, double x_frac);

    const Ciphertext& compact_unbatched_VerifyHE(const shared_ptr<seal_struct> seal_struct , K_MAC kmac, Ciphertext& x_int,
        Ciphertext& x_frac, mac_tag_ct& tag_he, bool squareDiff, int len, DS_performance_metrics* performanceMetrics);

    compact_unbatched_mac_tag compact_unbatched_mac(K_MAC& kmac, vector<double>& x_int, vector<double>& x_frac, ullong input_size);

};
