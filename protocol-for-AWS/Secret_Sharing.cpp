#include "Secret_Sharing.h"
#include "Tests.h"
#include <math.h>

using namespace utility;

Secret_Sharing::Secret_Sharing(enc_init_params_s enc_init_params)
{
    _enc_init_params = enc_init_params;
}

const Ciphertext& Secret_Sharing::Rec_CT(const vector<double>& cleartext_vec, const vector<double>& cleartext_for_cipher_vec, Ciphertext& x_int_FHE, Ciphertext& x_frac_FHE, const shared_ptr<seal_struct> context)
{

    Plaintext encoded_cleartext_vec, encoded_cleartext_for_cipher_vec;

    //high_resolution_clock::time_point start_rec_encode = utility::timer_start();

    context->encoder_ptr->encode(cleartext_vec, _enc_init_params.scale, encoded_cleartext_vec);

    context->encoder_ptr->encode(cleartext_for_cipher_vec, _enc_init_params.scale, encoded_cleartext_for_cipher_vec);

    //rec_encode+= utility::timer_end(start_rec_encode).count();

    context->evaluator_ptr->add_plain_inplace(x_frac_FHE, encoded_cleartext_vec);

    //high_resolution_clock::time_point start_rec_mul = utility::timer_start();
    context->evaluator_ptr->multiply_plain_inplace(x_int_FHE, encoded_cleartext_for_cipher_vec);
    //rec_multiply_plain+= utility::timer_end(start_rec_mul).count();

    //high_resolution_clock::time_point start_rescale_switch = utility::timer_start();
    context->evaluator_ptr->rescale_to_next_inplace(x_int_FHE);

    context->evaluator_ptr->mod_switch_to_next_inplace(x_frac_FHE);
    //rec_rescale+= utility::timer_end(start_rescale_switch).count();

    x_int_FHE.scale() = _enc_init_params.scale;


    context->evaluator_ptr->add_inplace(x_frac_FHE, x_int_FHE);

    //cout << "    +final Modulus chain index for x_frac_FHE " << context->context_ptr.get_context_data(x_frac_FHE.parms_id())->chain_index() << endl;
	//cout << " Exact SCALE in x_frac_FHE: " << log2(x_frac_FHE.scale()) << endl;


    return x_frac_FHE;
}



// Generate the initialization values of b and t from the derived key
// This function uses K bytes from the derived_key array where K = prime_byte_num*2
// It will take use the first prime_byte_num bytes for b_init and the second prime_byte_num bytes for t
// The number of bits in the generated number will match the number of bits in the prime.
void gen_b_t_init_values(ullong *b_init, ullong *t_init, int prime_bit_num, unsigned char *derived_key)
{
    int i;
    int shift = 0;
    int mask;
    int mask_pow;
    int prime_byte_num = ceil(prime_bit_num / 8.0);

    i = prime_bit_num;

    //init the first prime_byte_num-1 values
    for(i=0; i<prime_byte_num - 1; i++)
    {
        *b_init |= ((ullong)derived_key[i] << shift);
        *t_init |= ((ullong)derived_key[prime_byte_num + i] << shift);
        shift = shift + 8;
    }

    // for the final byte: if the amount of bits in the prime fills en entire byte - use a full byte from the derived_key
    // if not, generate a matching mask and leave only the number of bits according to the remaining number of bits in the prime
    mask_pow = ((prime_bit_num % 8) == 0) ? 8 : (prime_bit_num % 8);
    mask = (int)pow(2, mask_pow) - 1;
    *b_init |= (((ullong)derived_key[i] & mask) << shift);
    *t_init |= (((ullong)derived_key[prime_byte_num + i] & mask) << shift);

    /* debug
    cout << "prime_bit num: " << prime_bit_num << " prime byte num: "<< prime_byte_num << endl;
    cout << "derived_key: ";
    for (i=0; i<8;i++)
    {
        cout << std::hex << (ullong)derived_key[i] << " ";

    }
    cout << endl;

    cout << "b_init: " << std::hex << *b_init <<  endl;
    cout << "t_init: " << std::hex << *t_init <<  endl;
    exit(0);
    */
}

//PT secret sharing
//derive b,t with crypto++ hmac

sharePT_struct Secret_Sharing::Derive_b_t(SHARE_MAC_KEYS *keys, int prime_bits_to_bytes)
{

    ullong t1 = 0;
    int b1 = 0;

    for(int i = 0; i < prime_bits_to_bytes; i++)
    {
        t1 |= ((ullong)keys->get_next_byte() << 8*i);
    }

    b1 = keys->get_next_byte() & 0x1;

    sharePT_struct shared_struct;
    shared_struct.x_int = 0.0; // place holder
    shared_struct.x_frac = 0.0; // place holder
    shared_struct.t = t1 % _enc_init_params.prime;
    shared_struct.b = b1;

    return shared_struct;
}

sharePT_struct Secret_Sharing::Derive_b_t(CryptoPP::HMAC<CryptoPP::SHA256> hmac, int index)
{
    std::string derivation_data("storage_test_");
    derivation_data += std::to_string(index);
    int prime_bit_num = ceil(log2(_enc_init_params.prime));
    ullong b_init = 0;
    ullong t_init = 0;

    //calling derivation keyof crypto++
    std::string derived_key = utility::derive_rand_key(hmac, derivation_data);

    //long long key_derive= utility::timer_end(start_key_derive).count();

    //high_resolution_clock::time_point start_gen_init = utility::timer_start();
    gen_b_t_init_values(&b_init, &t_init, prime_bit_num, (unsigned char*)derived_key.c_str());
    //long long gen_init_b_t= utility::timer_end(start_gen_init).count();

    //cout <<"gen_init_b_t: "<<gen_init_b_t <<" key_derive "<< key_derive <<endl;

    int b = b_init / _enc_init_params.prime;
    llong t = t_init % _enc_init_params.prime;

    //cout.precision(32);
    //cout << "t: " << t <<" b: " <<b<< endl;

    sharePT_struct shared_struct;
    shared_struct.x_int = 0.0; // place holder
    shared_struct.x_frac = 0.0; // place holder
    shared_struct.t = t;
    shared_struct.b = b;
    return shared_struct;

}



sharePT_struct Secret_Sharing::gen_share(ullong x, SHARE_MAC_KEYS *secret_share_keys, int prime_bits_to_bytes)
{
    //high_resolution_clock::time_point start_derive = utility::timer_start();
    sharePT_struct shared_struct = Derive_b_t(secret_share_keys, prime_bits_to_bytes);
    //derive_share+= utility::timer_end(start_derive).count();

	//high_resolution_clock::time_point start_share_x_int = utility::timer_start();
	int x_int = ((x + shared_struct.t)/_enc_init_params.prime + shared_struct.b) % 2;
    //share_x_int+= utility::timer_end(start_share_x_int).count();

    //high_resolution_clock::time_point start_share_x_frac = utility::timer_start();
	ullong x_frac = ((x + shared_struct.t) % _enc_init_params.prime);
	//share_x_frac+= utility::timer_end(start_share_x_frac).count();

	shared_struct.x_int = (double)x_int;
	shared_struct.x_frac = (double) x_frac;

	return shared_struct;
}

nanoseconds Secret_Sharing::Share(vector<double> secret_num_vec, CryptoPP::HMAC<CryptoPP::SHA256> hmac, ullong num_of_secrets, std::ostringstream *os)
{
    ullong i, x;
    nanoseconds share_time{0};
    for (i=0; i<num_of_secrets; i++)
    {
        x = secret_num_vec[i];
        high_resolution_clock::time_point start_share = utility::timer_start();
        //high_resolution_clock::time_point start_derive = utility::timer_start();
        sharePT_struct shared_struct = Derive_b_t(hmac, i);
        //derive_share+= utility::timer_end(start_derive).count();

        int x_int = ((x + shared_struct.t)/_enc_init_params.prime + shared_struct.b) % 2;

        ullong x_frac = ((x + shared_struct.t) % _enc_init_params.prime);
        shared_struct.x_int = (double)x_int;
        shared_struct.x_frac = (double) x_frac;

        share_time += utility::timer_end(start_share);

        os->write(reinterpret_cast<const char*>(&shared_struct.x_int), sizeof(double));
        os->write(reinterpret_cast<const char*>(&shared_struct.x_frac), sizeof(double));

    }

    return share_time;

}

double Secret_Sharing::Rec_PT(double b_plus_t, int x_int, double x_frac) //PT reconstruct
{
	int z = floor(b_plus_t);
	double t = b_plus_t - z;
	double x = x_frac - t + (pow(-1, z)) * x_int + z;
	return x;
}
