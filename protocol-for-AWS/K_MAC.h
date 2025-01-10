#ifndef K_MAC_H
#define K_MAC_H

#include "Utility.h"


class K_MAC
{
    public:
        vector<double> a_int;
        vector<double> a_frac;
        vector<double> b;
        vector<double> c_alpha;
        vector<double> d_alpha;

        K_MAC(ullong prime);
        virtual ~K_MAC();

        virtual void derive_abcd(CryptoPP::HMAC<SHA256>& hmac, std::string derived_key, ullong start_index, ullong amount);


    protected:
        ullong _prime;

    private:
        //ullong _prime;
};

class SHARE_MAC_KEYS
{
    public:
        SHARE_MAC_KEYS() {};
        SHARE_MAC_KEYS(int key_length);

        virtual ~SHARE_MAC_KEYS();

        int key_len;
        vector<byte> keys;
        int keys_iter;

        void gen_keys(byte* key_tag, int key_tag_len, std::string info);
        byte get_next_byte(void);

};


class K_MAC_Batched : public K_MAC
{
    public:
        vector<double> c_beta;
        vector<double> d_beta;
        K_MAC_Batched(ullong prime); //ctot
        //no need for dtor since it's derived from base class

        void derive_a (SHARE_MAC_KEYS *kmac_keys, ullong start_index, ullong ct_max_index, int bytes_per_a);
        void derive_bcd (SHARE_MAC_KEYS *kmac_keys, int amount, int bytes_per_cd, int start_iter_index);

};

#endif // K_MAC_H
