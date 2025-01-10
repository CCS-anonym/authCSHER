#include "K_MAC.h"

K_MAC::K_MAC(ullong prime)
{
    _prime = prime;
}


K_MAC::~K_MAC()
{
    //dtor
}



void K_MAC::derive_abcd(CryptoPP::HMAC<SHA256>& hmac, std::string key, ullong start_index, ullong amount)
{
    for (int i = 0; i < amount; i++)
    {
        std::string derivation_data = key + std::to_string(start_index);
        std::string derived_key = utility::derive_rand_key(hmac, derivation_data);

        ullong a1_int = (((ullong)derived_key[0] << 48) | ((ullong)derived_key[1] << 40) | ((ullong)derived_key[2] << 32) | ((ullong)derived_key[3] << 24) | ((ullong)derived_key[4] << 16) | ((ullong)derived_key[5] << 8) | (ullong)(derived_key[6]));
        ullong a1_frac = (((ullong)derived_key[7] << 48) | ((ullong)derived_key[8] << 40) | ((ullong)derived_key[9] << 32) | ((ullong)derived_key[10] << 24) | ((ullong)derived_key[11] << 16) | ((ullong)derived_key[12] << 8) | (ullong)(derived_key[13]));
        ullong b1 =  (((ullong)derived_key[24] << 48) | ((ullong)derived_key[25] << 40) | ((ullong)derived_key[26] << 32) | ((ullong)derived_key[27] << 24) | ((ullong)derived_key[28] << 16) | ((ullong)derived_key[29] << 8) | (ullong)(derived_key[30]));
        ullong c1  = (((ullong)derived_key[14] << 48) | ((ullong)derived_key[15] << 40) | ((ullong)derived_key[16] << 32) | ((ullong)derived_key[17] << 24) | ((ullong)derived_key[18] << 16) | ((ullong)derived_key[19] << 8) | (ullong)(derived_key[20]));

        a_int.push_back(fmod(a1_int, _prime));
        a_frac.push_back(fmod(a1_frac, _prime));
        b.push_back(fmod(b1, _prime));
        c_alpha.push_back(fmod(c1, _prime));
        d_alpha.push_back(((unsigned int)(derived_key[31]) % 2));

        start_index++;
    }
}

K_MAC_Batched::K_MAC_Batched(ullong _prime) : K_MAC(_prime)
{}

SHARE_MAC_KEYS::SHARE_MAC_KEYS(int key_length)
{
    key_len = key_length;
    keys_iter = 0;
    keys.reserve(key_len);
}

SHARE_MAC_KEYS::~SHARE_MAC_KEYS()
{
}


void SHARE_MAC_KEYS::gen_keys(byte* key_tag, int key_tag_len, std::string info)
{
        utility::derive_rand_key_hkdf(key_tag, key_tag_len,info, keys, key_len);
}

byte SHARE_MAC_KEYS::get_next_byte(void)
{

    if (keys_iter < key_len)
    {
        keys_iter++;
        return keys[keys_iter];
    }

    perror("Key iterator exceeded key array size");
    cout << "key length: " << key_len <<  " keys_iter: " << keys_iter << endl;
    exit(1);
}


void K_MAC_Batched::derive_a(SHARE_MAC_KEYS *kmac_keys, ullong start_index, ullong ct_max_index, int bytes_per_a)
{
    for(int i = start_index; i < start_index + ct_max_index; i++)
    {
        ullong a1_int = 0;
        ullong a1_frac = 0;

        for (int j = 0; j < bytes_per_a; j++)
        {
                a1_int |= ((ullong)kmac_keys->get_next_byte() << 8*j);
                a1_frac |= ((ullong)kmac_keys->get_next_byte() << 8*j);
        }

        a_int.push_back(fmod(a1_int, _prime));
        a_frac.push_back(fmod(a1_frac, _prime));
	}
}

void K_MAC_Batched::derive_bcd(SHARE_MAC_KEYS *kmac_keys, int amount, int bytes_per_bc, int start_iter_index)
{
    // the bcd parameters are extracted from the indices of the buffer after the a values
    // while the DO extracts them by order, the dest extracts the bcd values after the first batch of a values.
    // in order to maintain consistency between the servers, we need to move the iterator to the relevant location
    // and then move it back. It is not the most elegant solution, but it works.

    int curr_iter = kmac_keys->keys_iter;
    kmac_keys->keys_iter = start_iter_index;
    for(int i=0; i < amount; i++)
    {
        ullong b1 = 0;
        ullong c1_alpha = 0;
        ullong c1_beta = 0;
        byte d1;

        for (int j = 0; j < bytes_per_bc; j++)
        {
                b1 |= ((ullong)kmac_keys->get_next_byte() << 8*j);
                c1_alpha |= ((ullong)kmac_keys->get_next_byte() << 8*j);
                c1_beta |= ((ullong)kmac_keys->get_next_byte() << 8*j);
        }

        d1 = kmac_keys->get_next_byte();
        b.push_back(fmod(b1, _prime));
        c_alpha.push_back(fmod(c1_alpha, _prime));
        c_beta.push_back(fmod(c1_beta, _prime));
        d_alpha.push_back(d1 & 0x1);
        d_beta.push_back(d1 & 0x2);
    }

    kmac_keys->keys_iter = curr_iter;

}




