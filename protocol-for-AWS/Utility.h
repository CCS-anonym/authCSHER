#pragma once
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include "seal/seal.h"
#include <aws/core/Aws.h>
#include <aws/s3/S3Client.h>
#include "Constants.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/files.h"
#include "cryptopp/hex.h"
#include "cryptopp/sha.h"
#include "cryptopp/hmac.h"
#include "cryptopp/hkdf.h"

using namespace CryptoPP;
using namespace seal;
using namespace std::chrono;
using namespace Aws;
using std::endl;
using std::cout;
using std::vector;
using std::string;
using std::tuple;

inline std::string glob_str = { 0 }; //define string for timer as global

class S3Utility{

private:
    Aws::S3::S3Client m_s3_client;
public:
    S3Utility(const Aws::String& region);
    ~S3Utility(){};
    const bool load_from_bucket(const Aws::String& objectKey, const Aws::String& fromBucket, int size, char* buffer);
    const bool save_to_bucket(const Aws::String& object_key, const Aws::String& to_bucket, std::string buffer);

};

namespace utility
{
    struct enc_init_params_s
    {
        ullong prime;
        ullong prime_minus_1;
        int polyDegree;
        int max_ct_entries;
        double scale;
        std::vector<int> bit_sizes;
        int float_precision_for_test;
        int num_of_bits_prime;
        int prime_bits_to_bytes;

        enc_init_params_s& operator=(const enc_init_params_s& a)
        {
            prime = a.prime;
            prime_minus_1 = a.prime_minus_1;
            polyDegree = a.polyDegree;
            max_ct_entries = a.max_ct_entries;
            scale = a.scale;
            bit_sizes = a.bit_sizes;
            float_precision_for_test = a.float_precision_for_test;
            num_of_bits_prime = (std::log2(a.prime));
            prime_bits_to_bytes = std::ceil(std::log2(a.prime) / 8.0);

            return *this;
        }
    };

    //file management funcs
	void save_to_file(const char* file_name, size_t size, const char* stream); //storing to file, gets size in blocks of 128 bits
	void load_from_file(std::string file_name, size_t no_blocks, char* stream);//downloading from file gets size in blocks of 128 bits

	void load_from_file(std::string file_name, char* stream);//downloading from file gets size in blocks of 128 bits


    bool GetEncryptionParamsFromBucket(const Aws::String& objectKey, const Aws::String& fromBucket, const Aws::String& region, EncryptionParameters& parms);
    bool GetPublicKeyFromBucket(const Aws::String& objectKey, const Aws::String& fromBucket, const Aws::String& region, SEALContext context_ptr, seal::PublicKey& pk_fhe);
    bool GetSecretKeyFromBucket(const Aws::String& objectKey, const Aws::String& fromBucket, const Aws::String& region, SEALContext context_ptr, SecretKey& sk_fhe);

    //file management funcs ONLY for FHE ciphertext
	void save_fhe_to_file(std::string file_name, Ciphertext ct_input);
	void load_from_fhe_file(std::string file_name, Ciphertext ct_output, SEALContext context);


	double x_gen(double min, double max); // generate random x in range - for share an input gen
	vector<double> x_gen_int(int min, ullong max, ullong amount);
    std::string derive_rand_key(CryptoPP::HMAC<SHA256> hmac, std::string derivation_data);
    void derive_rand_key_hkdf(byte* key_tag, int key_tag_len, std::string cur_derivation_data, std::vector<byte> &keys, int key_len);
	void print_vector(std::vector<double> vec, std::size_t print_size, int prec); //prints print_size objects in vector, prec spots of precision

	high_resolution_clock::time_point timer_start();
	nanoseconds timer_end(high_resolution_clock::time_point start);
	void send_timer_to_stream(int i, nanoseconds duration, const char* object_name);
	void print_timer_excel(); //prints global str to excel file

    const char* get_row_mat(const char* file_name, char* row_matrix); //creates a vector of matrix from excel
    const char* get_field(char* line, int num); //gets field in matrix
    vector<double> get_vector_from_csv(const char* file_name);

    std::string serialize_fhe(Ciphertext ct_input);
    void deserialize_fhe(std::string str, Ciphertext& ct_output, SEALContext& context);
    void deserialize_fhe(const char* str, std::size_t size, Ciphertext& ct_output, SEALContext& context);

    std::ofstream openMetricsFile(int input_size, string metrics_file_name);
    void InitEncParams(enc_init_params_s *enc_init_params, string fileName);

};

/*
how to check timer for each function:
1) create an instance of class i.e: Functions_Timer Functions_Timer1;
2) one line before given function, auto start = timer_Start()
3) right after function: duration = timer_end(start)
4) send_timer_to_stream(counter, duration, object name)
5) end of main - add print_timer_excel(); //prints global str to excel file
*/
