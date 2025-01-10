#include "MAC.h"
#include <random>
#include <chrono>

using namespace utility;

MAC::MAC(enc_init_params_s enc_init_params)
{
    _enc_init_params = enc_init_params;
}


single_mac_tag MAC::mac_single(single_key_mac kmac, double x) {

	auto dvY = lldiv((kmac.a * x + kmac.b), _enc_init_params.prime);
	double y_r = double(dvY.rem); //y_r = (a * x + b) % P;
	double y_q = double(dvY.quot); //y_q = (a * x + b) / P;
	auto dvZ = lldiv((y_q + kmac.c), _enc_init_params.prime);
	double z_r = double(dvZ.rem); //z_r = (y_q + c) %p
	double z_qmskd = fmod((dvZ.quot + kmac.d), 2);//z_qmskd = (y_q + c) /P +d %2;
	return single_mac_tag{ z_qmskd, z_r , y_r };
}

//cleartext verify on single input
bool MAC::verify_single(single_key_mac kmac, double x, single_mac_tag tag) {
	double a = kmac.a; double b = kmac.b; double c = kmac.c; double d = kmac.d;
	/*
	z_q = pow(-1, d) * (tag.z_qmskd - d);
	y_tag = ((z_q * P + tag.z_r) - c) * P + tag.y_r;
	y = a * x + b;
    diff = y - y_tag;
	 */
	double z_q = pow(-1, d) * (tag.z_qmskd - d);
	double y_tag = ((z_q * _enc_init_params.prime + tag.z_r) - c) * _enc_init_params.prime + tag.y_r;
	double y = (a * x) + b;
	double diff = y - y_tag;

	if (diff != 0) {
		return false;
	}
	else {
		return true;
	}

}


//derivation of a single mac key from hmac and index
single_key_mac MAC::Derive_kmac_single(CryptoPP::HMAC<SHA256> hmac, int index)
{
	std::string derivation_data("storage_test_MAC_");
	derivation_data += std::to_string(index);

	std::string derived_key = utility::derive_rand_key(hmac, derivation_data);

	int d = abs(int(derived_key[31]) % 2);
	//cout << "index is: " <<index <<" Derived last byte " << d<< endl;//std::hex <<  (int)derived_key[3] << " " << std::dec << (int)derived_key[3] << endl;

	unsigned long long a1 = (((unsigned long long)derived_key[0] << 48) | ((unsigned long long)derived_key[1] << 40) | ((unsigned long long)derived_key[2] << 32) | ((unsigned long long)derived_key[3] << 24) | ((unsigned long long)derived_key[4] << 16) | ((unsigned long long)derived_key[5] << 8) | (unsigned long long)(derived_key[6]));
	unsigned long long b1 = (((unsigned long long)derived_key[7] << 48) | ((unsigned long long)derived_key[8] << 40) | ((unsigned long long)derived_key[9] << 32) | ((unsigned long long)derived_key[10] << 24) | ((unsigned long long)derived_key[11] << 16) | ((unsigned long long)derived_key[12] << 8) | (unsigned long long)(derived_key[13]));
	unsigned long long c1 = (((unsigned long long)derived_key[14] << 48) | ((unsigned long long)derived_key[15] << 40) | ((unsigned long long)derived_key[16] << 32) | ((unsigned long long)derived_key[17] << 24) | ((unsigned long long)derived_key[18] << 16) | ((unsigned long long)derived_key[19] << 8) | (unsigned long long)(derived_key[20]));

	double a = fmod(a1, _enc_init_params.prime);
	double b = fmod(b1, _enc_init_params.prime);
	double c = fmod(c1, _enc_init_params.prime);
	//cout.precision(10);
	//cout << "a: " << a<<" b: "<<b <<" c: "<<c<<endl;

	single_key_mac kmac;
	kmac.a = a;
	kmac.b = b;
	kmac.c = c;
	kmac.d = d;

	return kmac;

}

Ciphertext& MAC::mult_ct_pt_inplace(const shared_ptr<seal_struct> seal_struct, Ciphertext& ct,
	const Plaintext& pt) {
	seal_struct->evaluator_ptr->multiply_plain_inplace(ct, pt);
	seal_struct->evaluator_ptr->rescale_to_next_inplace(ct);
	ct.scale() = _enc_init_params.scale;
	return ct;
}


/*
In Verify over HE we returns ctxt of diff between computed ct and original one. And apply:

	z_q = pow(-1, d) * (tag.z_qmskd - d);
	y_tag = ((z_q * p + tag.z_r) - c) * p + tag.y_r;
	y = a * x + b;
    diff = y - y_tag;

for efficiency over FHE we change it into:

    for i in vector:
    y_comp = (-1)^d[i] * p^2 * z_qmskd + z_r * p + y_r + (-d[i]) * (-1)^ d[i] * p^2 - c[i] * p
    y= a[i] * x + b[i]
    diff = y_comp - y


*/
const Ciphertext& MAC::verifyHE(const shared_ptr<seal_struct> seal_struct , const key_mac& kmac, Ciphertext& x,
	mac_tag_ct& tag_he, bool squareDiff, int len, DS_performance_metrics* performanceMetrics) {

	// this function computes the following:
	// In cleartext form: (-1)^d*(-d)*p^2-c*p-b
	// In ciphertext form: p^2*(-1)^d*z_qmskd+t_r -ax
	// It then adds the cleartext and the ciphertext values. When the value is close to 0, the mac is valid

	double p_square = _enc_init_params.prime * _enc_init_params.prime;
	vector<double> signPSquare(len, p_square); //if d=0 then: (-1)^d *p^2 = p^2
	vector<double> cleartext_calc(len, 0); //vector to sum all cleartext operations in verify

	high_resolution_clock::time_point start_verify = utility::timer_start();
	for (int i = 0; i < len; i++) {
		if (kmac.d.get()->at(i) == 1) {
			signPSquare[i] = -p_square; // if d=1 then: (-1)^d *p^2 = -p^2
			cleartext_calc[i] = p_square - kmac.c.get()->at(i) * _enc_init_params.prime - kmac.b.get()->at(i); // (-1)^d*(-d)*p^2-c*p-b
		}
		else {//d=0
			cleartext_calc[i] =  - kmac.c.get()->at(i) * _enc_init_params.prime - kmac.b.get()->at(i); //if d=0: -c*p -b
		}
	}

	Plaintext pt_signPSquare, cleartext_calc_pt;
	seal_struct->encoder_ptr->encode(signPSquare, _enc_init_params.scale, pt_signPSquare);

	mult_ct_pt_inplace(seal_struct, *tag_he.z_qmskd_ct, pt_signPSquare); //(-1)^d *p^2 *z_qmskd

	Ciphertext y_comp;
	seal_struct->evaluator_ptr->mod_switch_to_inplace(*tag_he.t_r_ct, tag_he.z_qmskd_ct.get()->parms_id());
	seal_struct->evaluator_ptr->add(*tag_he.t_r_ct, *tag_he.z_qmskd_ct, y_comp); //(-d)*(-1)^d* p^2 * z_qmskd+ t_r

	Plaintext a_pt;
	seal_struct->encoder_ptr->encode(*kmac.a, x.parms_id(), _enc_init_params.scale, a_pt);
	mult_ct_pt_inplace(seal_struct, x, a_pt); // ax

	seal_struct->evaluator_ptr->sub(y_comp, x, x);

	seal_struct->encoder_ptr->encode(cleartext_calc, x.parms_id(), _enc_init_params.scale, cleartext_calc_pt);
	seal_struct->evaluator_ptr->add_plain_inplace(x, cleartext_calc_pt);

    performanceMetrics->verify += utility::timer_end(start_verify).count();
    //apply square diffs
	if (squareDiff)
    {
        high_resolution_clock::time_point start_square_diff = utility::timer_start();
		seal_struct->evaluator_ptr->square_inplace(x); //computing sqauare diff
		seal_struct->evaluator_ptr->relinearize_inplace(x, *seal_struct->relink_ptr); //must do after ctxt * ctxt multiplication
		seal_struct->evaluator_ptr->rescale_to_next_inplace(x); //see if necessary for decryption, possible
		x.scale() = _enc_init_params.scale;
		performanceMetrics->square_diff += utility::timer_end(start_square_diff).count();
	}

	return x;
}

K_MAC MAC::Derive_compact_kmac_unbatched_single(CryptoPP::HMAC<SHA256>& hmac, ullong start_index, ullong amount)
{
    std::string derivation_data("storage_test_MAC_");

    K_MAC kmac(_enc_init_params.prime);

    kmac.derive_abcd(hmac, derivation_data, start_index, amount);

    return kmac;

}



//deriving one compact kmac, such that all of vector indexes are for a int, a frac, and final index is for
// b, c, d in kmac.
K_MAC_Batched MAC::Derive_compact_kmac_single(CryptoPP::HMAC<SHA256>& hmac, ullong start_index, ullong amount)
{
    std::string derivation_data("storage_test_MAC_");

    K_MAC_Batched kmac(_enc_init_params.prime);

    kmac.derive_abcd(hmac, derivation_data, start_index, amount);

    //cout << "inside: kmac.a_int: " << kmac.a_int[0] << " kmac.a_frac: " << kmac.a_frac[0] << " kmac.b: " << kmac.b << " kmac.c_alpha: " << kmac.c_alpha[0] << " kmac.d_alpha: " << kmac.d_alpha[0] << endl;

    return kmac;
}

single_mac_tag MAC::single_compact_mac(K_MAC kmac, int index, double x_int, double x_frac) {

    /*
    y_r = sum(a_i*x_i)+b mod p
    y_q = (sum(a_i*x_i)+b) / p
    y_alpha = y_q / p
    y_alpha_frac_ = (y_alpha + c_alpha ) mod p
    y_alpha_int = ((y_alpha + c_alpha )  /p + d_alpha ) mod 2

    output: (y_r, y_alpha_int, y_alpha_frac)
    */

    double sum_dvY=(kmac.a_int[index]*x_int +kmac.a_frac[index]*x_frac + kmac.b[index]);

    //cout << "y: " << (kmac.a_int[0]*x_int +kmac.a_frac[0]*x_frac) << endl;

    auto dvY = lldiv(sum_dvY, _enc_init_params.prime);
	double y_r = double(dvY.rem); //y_r = (a_i * x_i + b) % P;
	double y_q = double(dvY.quot); //y_q = (a_i * x_i + b) / P;

	auto dvYalpha = lldiv(y_q + kmac.c_alpha[index] ,_enc_init_params.prime);
	double y_alpha_frac = dvYalpha.rem; //(y_alpha + c_alpha ) mod p
    double y_alpha_int = fmod((dvYalpha.quot + kmac.d_alpha[index]), 2); //(y_alpha + c_alpha )  /p + d_alpha ) mod 2

    /*
    cout.precision(14);
    cout <<"y_r: "<<y_r << " y_alpha_int: "<<y_alpha_int << " y_alpha_frac: "<<y_alpha_frac << endl;*/

	return single_mac_tag{ y_alpha_int, y_alpha_frac, y_r};
}


mac_tag_batched_optimized MAC::compact_mac_batched_optimized(K_MAC_Batched kmac, vector<double> y_vec)
{
    int i;
    double sum_dvY;
    double prime_square = std::pow(_enc_init_params.prime, 2);
    double y_r, y_q, y_alpha_frac, y_alpha_int, y_beta_frac, y_beta_int, alpha, beta;

    mac_tag_batched_optimized mac_optimized;

    for (i = 0; i< y_vec.size(); i++)
    {
        sum_dvY = y_vec[i];
        auto dvY = lldiv(sum_dvY, _enc_init_params.prime);
        y_r = double(dvY.rem); //y_r = (a_i * x_i + b) % P;
        y_q = double(dvY.quot); //y_q = (a_i * x_i + b) / P;

        auto alpha_beta = lldiv(y_q, _enc_init_params.prime);

        alpha = alpha_beta.quot; //y_q  / p
        auto dvYalpha = lldiv(alpha + kmac.c_alpha[i] ,_enc_init_params.prime);
        y_alpha_frac = dvYalpha.rem; //(alpha + c_alpha ) mod p
        y_alpha_int = fmod((dvYalpha.quot + kmac.d_alpha[i]), 2); //(alpha + c_alpha )  /p + d_alpha ) mod 2

        beta = alpha_beta.rem; //y_q  mod p
        auto dvYbeta = lldiv(beta + kmac.c_beta[i] ,_enc_init_params.prime);
        y_beta_frac = dvYbeta.rem; //(beta + c_beta ) mod p
        y_beta_int = fmod((dvYbeta.quot + kmac.d_beta[i]), 2); //((beta + c_beta )  /p + d_beta ) mod 2

        mac_optimized.mac_part1.push_back(y_alpha_frac * prime_square + y_beta_frac * _enc_init_params.prime + y_r);
        mac_optimized.mac_part2.push_back((int(y_alpha_int) <<1 )| int(y_beta_int) );
    }

    return mac_optimized;
}


compact_mac_tag MAC::compact_mac(vector<K_MAC_Batched>& kmac_vec, vector<vector<double>>& x_int, vector<vector<double>>& x_frac, ullong input_size) {

    /**
    y_r = sum(a_i*x_i)+b mod p
    y_q = (sum(a_i*x_i)+b) / p
    y_alpha = y_q / p
    y_alpha_frac_ = (y_alpha + c_alpha ) mod p
    y_alpha_int = ((y_alpha + c_alpha )  /p + d_alpha ) mod 2

    y_beta = y_q  mod p
    y_beta_frac_ = (y_beta + c_beta ) mod p
    y_beta_int = ((y_beta + c_beta )  /p + d_beta ) mod 2
    output: (y_r, y_alpha_int, y_alpha_fra, y_beta_int, y_beta_frac)
    **/

    int vec_size = std::min(int(input_size), _enc_init_params.max_ct_entries); // = data items in one  ctxt.
    int N_agg = ceil((input_size + 0.0) / _enc_init_params.max_ct_entries); //number of FHE  ciphertexts, derived automatically from user input
    int last_vec_size = (input_size%_enc_init_params.max_ct_entries == 0) ? vec_size : input_size % _enc_init_params.max_ct_entries;

    //cout <<"in MAC vec size: "<<vec_size <<" N_agg: "<<N_agg<<" last_vec_size: "<<last_vec_size <<" vec_size: "<<vec_size<<endl;

    int cur_vec_size = vec_size;
    //computing sum(a_i*x_i) +b
    vector<double> sum_dvY(vec_size, 0.0);
    for(int j=0; j<N_agg; j++){
        if(j==(N_agg-1)){
            cur_vec_size = last_vec_size;
        }
        for(int i=0; i< cur_vec_size; i++){
            sum_dvY[i]+=(kmac_vec[i].a_int[j]*x_int[j][i] +kmac_vec[i].a_frac[j]*x_frac[j][i]);
            if(j==0){
                sum_dvY[i]+= kmac_vec[i].b[i]; //adding b only once for each line
                //cout<<"added b in mac"<<endl;
            }
        }
    }

    vector<double> y_r_vec(vec_size, 0);
    vector<double>  y_alpha_int_vec(vec_size, 0);
    vector<double> y_alpha_frac_vec(vec_size, 0);
    vector<double> y_beta_int_vec(vec_size, 0);
    vector<double> y_beta_frac_vec(vec_size, 0);
    cur_vec_size = vec_size;
    //computing mac tag from above sum

    for(int i=0; i< cur_vec_size; i++)
    {
        auto dvY = lldiv(sum_dvY[i], _enc_init_params.prime);
        y_r_vec[i] = double(dvY.rem); //y_r = (a_i * x_i + b) % P;
        double y_q = double(dvY.quot); //y_q = (a_i * x_i + b) / P;

        auto alpha_beta = lldiv(y_q, _enc_init_params.prime);

        double alpha = alpha_beta.quot; //y_q  / p
        auto dvYalpha = lldiv(alpha + kmac_vec[i].c_alpha[0] ,_enc_init_params.prime);
        y_alpha_frac_vec[i] += dvYalpha.rem; //(alpha + c_alpha ) mod p
        y_alpha_int_vec[i] += fmod((dvYalpha.quot + kmac_vec[i].d_alpha[0]), 2); //(alpha + c_alpha )  /p + d_alpha ) mod 2

        double beta = alpha_beta.rem; //y_q  mod p
        auto dvYbeta = lldiv(beta + kmac_vec[i].c_beta[0] ,_enc_init_params.prime);
        y_beta_frac_vec[i] += dvYbeta.rem; //(beta + c_beta ) mod p
        y_beta_int_vec[i] += fmod((dvYbeta.quot + kmac_vec[i].d_beta[0]), 2); //((beta + c_beta )  /p + d_beta ) mod 2
    }


    //cout.precision(14);
    //cout <<"y_r: "<<y_r_vec[0] << " y_alpha_int: "<<y_alpha_int_vec[0] << " y_alpha_frac: "<<y_alpha_frac_vec[0] << " y_beta_int: "<<y_beta_int_vec[0] << " y_beta_frac: "<< y_beta_frac_vec[0] <<endl;

    compact_mac_tag tag;
    tag.y_r = make_shared<vector<double>>(y_r_vec);
    tag.y_alpha_int = make_shared<vector<double>>(y_alpha_int_vec);
    tag.y_alpha_frac = make_shared<vector<double>>(y_alpha_frac_vec);
    tag.y_beta_int = make_shared<vector<double>>(y_beta_int_vec);
    tag.y_beta_frac = make_shared<vector<double>>(y_beta_frac_vec);

	return tag;
}

Ciphertext MAC::verifyHE_batched_y(const shared_ptr<seal_struct> seal_struct , K_MAC_Batched kmac, Ciphertext ct_x_int, Ciphertext ct_x_frac, DS_performance_metrics* performanceMetrics)
{
    Ciphertext ct_result;
    Plaintext pt_a_int, pt_a_frac;

    high_resolution_clock::time_point start_verify = utility::timer_start();

	seal_struct->encoder_ptr->encode(kmac.a_int, _enc_init_params.scale, pt_a_int);
	seal_struct->encoder_ptr->encode(kmac.a_frac, _enc_init_params.scale, pt_a_frac);

	mult_ct_pt_inplace(seal_struct, ct_x_int, pt_a_int);
	mult_ct_pt_inplace(seal_struct, ct_x_frac, pt_a_frac);

	seal_struct->evaluator_ptr->add(ct_x_int, ct_x_frac, ct_result);

	performanceMetrics->verify += utility::timer_end(start_verify).count();

    return ct_result;

}

Ciphertext MAC::verifyHE_batched_y_tag(const shared_ptr<seal_struct> seal_struct , int len_vec, K_MAC_Batched kmac, Ciphertext ct_tr, Ciphertext ct_alpha_int, Ciphertext ct_beta_int, DS_performance_metrics* performanceMetrics)
{
    double p_square = _enc_init_params.prime * _enc_init_params.prime;
	double p_triple = p_square * _enc_init_params.prime;
	vector<double> signPTriple(len_vec, 1); //if d=0 then: (-1)^d *p^3 = p^2
	vector<double> signPSquare(len_vec, 1); //if d=0 then: (-1)^d *p^2 = p^3
	vector<double> cleartext_calc(len_vec, 0); //vector to sum all cleartext operations in verify

    high_resolution_clock::time_point start_verify = utility::timer_start();

    for (int i = 0; i < len_vec; i++)
    {
		if (kmac.d_alpha[i] == 1) {
			signPTriple[i] = -1; // if d=1 then: (-1)^d_alpha *p^3 = -p^3
			cleartext_calc[i] += p_triple - kmac.c_alpha[i] * p_square; // (-1)^d_alpha*(-d_alpha)*p^3-c_alpha*p^2
		}
		else {//d=0
			cleartext_calc[i] +=  - kmac.c_alpha[i]* p_square ;//if d=0: -c_alpha*p^2
		}

		if (kmac.d_beta[i] == 1) {
			signPSquare[i] = -1; // if d=1 then: (-1)^d_beta *p^2 = -p^2
			cleartext_calc[i] += p_square - kmac.c_beta[i] * _enc_init_params.prime ; // (-1)^d_beta*(-d_beta)*p^2-c_beta*p
		}
		else {//d=0
			cleartext_calc[i] +=  - kmac.c_beta[i] * _enc_init_params.prime ;//if d=0: -c_beta*p
		}

		cleartext_calc[i] -= kmac.b[i];
	}

    Plaintext pt_signPTriple, pt_signPSquare, cleartext_calc_pt;
	seal_struct->encoder_ptr->encode(signPTriple, _enc_init_params.scale, pt_signPTriple);
	seal_struct->encoder_ptr->encode(signPSquare, _enc_init_params.scale, pt_signPSquare);

	Ciphertext y_comp;

	mult_ct_pt_inplace(seal_struct, ct_alpha_int, pt_signPTriple); //(-1)^d_alpha*p^3* y_alpha_int
	mult_ct_pt_inplace(seal_struct, ct_beta_int, pt_signPSquare); //(-1)^d_beta*p^2* y_beta_int
    seal_struct->evaluator_ptr->add(ct_alpha_int, ct_beta_int, y_comp); //(-1)^d_alpha*p^3* y_alpha_int + (-1)^d_beta*p^2* y_beta_int

	seal_struct->evaluator_ptr->mod_switch_to_inplace(ct_tr, y_comp.parms_id());
	seal_struct->evaluator_ptr->add_inplace(y_comp, ct_tr); //(-1)^d_alpha*p^3* y_alpha_int + (-1)^d_beta*p^2* y_beta_int+y_t

    seal_struct->encoder_ptr->encode(cleartext_calc, y_comp.parms_id(), _enc_init_params.scale, cleartext_calc_pt);
	seal_struct->evaluator_ptr->add_plain_inplace(y_comp, cleartext_calc_pt);

	performanceMetrics->verify += utility::timer_end(start_verify).count();

	return y_comp;

}



compact_unbatched_mac_tag MAC::compact_unbatched_mac(K_MAC& kmac, vector<double>& x_int, vector<double>& x_frac, ullong input_size) {

    /**
    y_r = (a_i*x_i)+b mod p
    y_q = (a_i*x_i)+b) / p
    y_alpha_frac_ = (y_q + c_alpha ) mod p
    y_alpha_int = ((y_q + c_alpha )  /p + d_alpha ) mod 2

    output: (y_r, y_alpha_int, y_alpha_frac)
    **/

    int vec_size = x_int.size(); // = data items in one  ctxt.

    //cout <<"in MAC vec size: "<<vec_size <<endl;
    //computing a_i*x_i +b
    vector<double> sum_dvY, y_r_vec, y_alpha_int_vec, y_alpha_frac_vec;

    for(int i=0; i< vec_size; i++){
        sum_dvY.push_back(kmac.a_int[i]*x_int[i] +kmac.a_frac[i]*x_frac[i] + kmac.b[i]);

        auto dvY = lldiv(sum_dvY[i], _enc_init_params.prime);
        y_r_vec.push_back(double(dvY.rem)); //y_r = (a_i * x_i + b) % P;
        double y_q = double(dvY.quot); //y_q = (a_i * x_i + b) / P;

        auto dvYalpha = lldiv(y_q + kmac.c_alpha[i] ,_enc_init_params.prime);
        y_alpha_frac_vec.push_back(dvYalpha.rem); //(y_alpha + c_alpha ) mod p
        y_alpha_int_vec.push_back(fmod((dvYalpha.quot + kmac.d_alpha[i]), 2)); //(y_alpha + c_alpha )  /p + d_alpha ) mod 2
    }

    //cout.precision(14);
    //cout <<"y_r: "<<y_r_vec[0] << " y_alpha_int: "<<y_alpha_int_vec[0] << " y_alpha_frac: "<<y_alpha_frac_vec[0] << endl;

    compact_unbatched_mac_tag tag;
    tag.y_r = make_shared<vector<double>>(y_r_vec);
    tag.y_alpha_int = make_shared<vector<double>>(y_alpha_int_vec);
    tag.y_alpha_frac = make_shared<vector<double>>(y_alpha_frac_vec);

	return tag;
}


const Ciphertext& MAC::compact_unbatched_VerifyHE(const shared_ptr<seal_struct> seal_struct , K_MAC kmac, Ciphertext& x_int,
	Ciphertext& x_frac, mac_tag_ct& tag_he, bool squareDiff, int len, DS_performance_metrics* performanceMetrics)
{

	// this function computes the following:
	// In cleartext form: (-1)^d*(-d)*p^2-c*p-b
	// In ciphertext form: p^2*(-1)^d*z_qmskd+t_r -ax
	// It then adds the cleartext and the ciphertext values. When the value is close to 0, the mac is valid

	double p_square = _enc_init_params.prime * _enc_init_params.prime;
	vector<double> signPSquare(len, p_square); //if d=0 then: (-1)^d *p^2 = p^2
	vector<double> cleartext_calc(len, 0); //vector to sum all cleartext operations in verify

	high_resolution_clock::time_point start_verify = utility::timer_start();
	for (int i = 0; i < len; i++) {
		if (kmac.d_alpha[i] == 1) {
			signPSquare[i] = -p_square; // if d=1 then: (-1)^d *p^2 = -p^2
			cleartext_calc[i] = p_square - kmac.c_alpha[i] * _enc_init_params.prime - kmac.b[i]; // (-1)^d*(-d)*p^2-c*p-b
		}
		else {//d=0
			cleartext_calc[i] =  - kmac.c_alpha[i] * _enc_init_params.prime - kmac.b[i] ;//if d=0: -c*p-b
		}
	}

	Plaintext pt_signPSquare, cleartext_calc_pt;
	seal_struct->encoder_ptr->encode(signPSquare, _enc_init_params.scale, pt_signPSquare);

	mult_ct_pt_inplace(seal_struct, *tag_he.z_qmskd_ct, pt_signPSquare); //(-1)^d *p^2 *z_qmskd

	Ciphertext y_comp;
	seal_struct->evaluator_ptr->mod_switch_to_inplace(*tag_he.t_r_ct, tag_he.z_qmskd_ct.get()->parms_id());
	seal_struct->evaluator_ptr->add(*tag_he.t_r_ct, *tag_he.z_qmskd_ct, y_comp); //(-d)*(-1)^d* p^2 * z_qmskd+ t_r


    seal_struct->encoder_ptr->encode(cleartext_calc, y_comp.parms_id(), _enc_init_params.scale, cleartext_calc_pt);
	seal_struct->evaluator_ptr->add_plain_inplace(y_comp, cleartext_calc_pt);

	Plaintext a_int_pt, a_frac_pt;
	seal_struct->encoder_ptr->encode(kmac.a_int, x_int.parms_id(), _enc_init_params.scale, a_int_pt);
	seal_struct->encoder_ptr->encode(kmac.a_frac, x_frac.parms_id(), _enc_init_params.scale, a_frac_pt);
	mult_ct_pt_inplace(seal_struct, x_int, a_int_pt);
	mult_ct_pt_inplace(seal_struct, x_frac, a_frac_pt);

	seal_struct->evaluator_ptr->add_inplace(x_int, x_frac);

	seal_struct->evaluator_ptr->sub(y_comp, x_int, x_int); //compute y-y' , output should be 0

    performanceMetrics->verify += utility::timer_end(start_verify).count();
    //apply square diffs
	if (squareDiff)
    {
        high_resolution_clock::time_point start_square_diff = utility::timer_start();
		seal_struct->evaluator_ptr->square_inplace(x_int); //computing sqauare diff
		seal_struct->evaluator_ptr->relinearize_inplace(x_int, *seal_struct->relink_ptr); //must do after ctxt * ctxt multiplication
		seal_struct->evaluator_ptr->rescale_to_next_inplace(x_int); //see if necessary for decryption, possible
		x_int.scale() = _enc_init_params.scale;
		performanceMetrics->square_diff += utility::timer_end(start_square_diff).count();
	}

	return x_int;

}


