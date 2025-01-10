//
// Created by Sapir, Boaz on 07/06/2021.
//
#include "Data_Owner.h"
#include "../Utility.h"
#include <aws/core/Aws.h>
#include <aws/core/utils/logging/LogLevel.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/PutObjectRequest.h>
#include <iomanip>
#include <cryptopp/osrng.h>

using namespace Aws;


std::ostream& operator<<(std::ostream& out, const DO_performance_metrics& doPerformanceMetrics) {
    return out << doPerformanceMetrics.share/1000 << "," <<doPerformanceMetrics.mac/1000 << "," << doPerformanceMetrics.upload_shared/1000 << "," <<
    doPerformanceMetrics.upload_sq/1000 << "," << doPerformanceMetrics.upload_sr/1000 << "," << doPerformanceMetrics.end2end/1000;}

std::string DO_performance_metrics::getHeader(){
    return "share,mac,upload shared,upload tag_sq,upload tag_sr, end2end_do";
}

// save the b/t generation key and the secret share/mac verify info to the bucket
long long saveKeyAndDataToBucket(S3Utility s3Utility, string key_str,  string plain_data, string dir_name, string file_bucket)
{

    s3Utility.save_to_bucket(file_bucket, awsparams::bucket_name, key_str);

    string file_name(dir_name);
    file_name.append("/");
    file_name.append(std::to_string(0));

    high_resolution_clock::time_point start_save = utility::timer_start();

    s3Utility.save_to_bucket(file_name.c_str(), awsparams::bucket_name, plain_data);

    long long share_time = utility::timer_end(start_save).count();
    return share_time;
}

Data_Owner::Data_Owner(string enc_init_params_file)
{
    InitEncParams(&_enc_init_params, enc_init_params_file);
}

// saves the secret vector to the AWS bucket
// the destination server then uses it for verification that the
// secret reconstruction worked. This is a feature for testing.
void Data_Owner::SaveSecertToBucket()
{
    SDKOptions options;
    //options.loggingOptions.logLevel = Utils::Logging::LogLevel::Debug;
    Aws::InitAPI(options);
    {
        S3Utility s3Utility(awsparams::region);
        std::string str1 = "";
        for (int i = 0; i < _secret_num_vec.size(); i++) {

            std::string num_str = std::to_string((ullong)_secret_num_vec[i]) + "\0";
            std::string padded_num_str = (_enc_init_params.float_precision_for_test > num_str.length()) ? std::string(_enc_init_params.float_precision_for_test - num_str.length(), '0') + num_str : num_str;
            str1.append(padded_num_str);
            }
        s3Utility.save_to_bucket("inputs", awsparams::bucket_name, str1);
    }
    Aws::ShutdownAPI(options);

}

// generate secret numbers
void Data_Owner::GenSecret(ullong input_size)
{
    _secret_num_vec = utility::x_gen_int(0, _enc_init_params.prime_minus_1, input_size);
}

// generate secret share
int Data_Owner::GenSecretShare(DO_performance_metrics& performanceMetrics)
{
    Secret_Sharing secret_sharing(_enc_init_params);
    string plain_x_int_frac;
    byte DS_key[KEY_SIZE_BYTES];
    CryptoPP::AutoSeededRandomPool rng;

    // generate secret share key
    rng.GenerateBlock(DS_key, KEY_SIZE_BYTES);

    //std::string DS_key_str(reinterpret_cast<byte*>(DS_key));

    nanoseconds share_time{0};
    std::ostringstream os;

    CryptoPP::HMAC<CryptoPP::SHA256> hmac((const byte*)DS_key, KEY_SIZE_BYTES);

    // generate secret shares
    share_time = secret_sharing.Share(_secret_num_vec, hmac, _secret_num_vec.size(), &os); //with hmac

    performanceMetrics.share = share_time.count();

    // write key and secret share files to AWS bucket
    plain_x_int_frac = os.str();

    SDKOptions options;
    //options.loggingOptions.logLevel = Utils::Logging::LogLevel::Debug;
    Aws::InitAPI(options);
    {
        S3Utility s3Utility(awsparams::region);

        performanceMetrics.upload_shared = saveKeyAndDataToBucket(s3Utility, reinterpret_cast<char*>(DS_key), plain_x_int_frac, string(CIPHERTEXTS_X_INT_FRAC_DIR), constants::SECRET_SHARE_KEY_FILENAME);
    }
    Aws::ShutdownAPI(options);

    return 1;
}


string gen_rand_key(int key_size){
    byte key[key_size];
    CryptoPP::AutoSeededRandomPool rng;

    rng.GenerateBlock(key, key_size);
    std::string encoded;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(encoded));
    encoder.Put(key, sizeof(key));
    encoder.MessageEnd();
    return encoded;

    //std::string key_str(reinterpret_cast<char*>(key), key_size);
    //return key_str;
}

// generate secret share and compact MAC
int Data_Owner::GenSecretShareAndCompactMAC(DO_performance_metrics& performanceMetrics, bool batched)
{
    Secret_Sharing secret_sharing(_enc_init_params);
    MAC mac(_enc_init_params);
    string plain_x_int_frac, plain_tag, plain_tag_beta;
    double calc_for_store;
    double prime_square = pow(_enc_init_params.prime, 2);

    mac_tag_batched_optimized optimized_mac;
    int prime_bits_to_bytes;
    int num_of_bits_prime = (std::log2(_enc_init_params.prime));
    int num_of_secret_shares = _secret_num_vec.size();

    // generate secret share key
    CryptoPP::AutoSeededRandomPool rng;
    byte DS_key[KEY_SIZE_BYTES];

    // generate secret share key
    rng.GenerateBlock(DS_key, KEY_SIZE_BYTES);

    CryptoPP::HMAC<CryptoPP::SHA256> hmac(DS_key, KEY_SIZE_BYTES);

    // generate MAC keys
    byte MAC_key[KEY_SIZE_BYTES];
    rng.GenerateBlock(MAC_key, KEY_SIZE_BYTES);
    CryptoPP::HMAC<CryptoPP::SHA256> hmac_tag(MAC_key, KEY_SIZE_BYTES);

    // generate secret shares and mac tags
    nanoseconds share_time{0};
    nanoseconds mac_time{0};
    std::ostringstream os, os_tag, os_tag_beta;
    vector<char> byteArr;

    vector<int> cur_indexes;
    int j=0;
    int mac_len = std::min(num_of_secret_shares, _enc_init_params.max_ct_entries);

    // calc the number of bytes needed for the mac "a" value according to the number of bits in the prime number
    // as all "a" values are in Zp
    prime_bits_to_bytes = std::ceil(num_of_bits_prime / 8.0);

    // calculate the number of bytes required for secret share b and t
    // we will need the prime number of bytes for t and another bit for b
    // currently this isn't optimized as we allocated a full byte for b.
    // this can be a point for future optimization
    int bytes_for_secret_share = num_of_secret_shares * (prime_bits_to_bytes + 1);
    SHARE_MAC_KEYS secret_share_keys(bytes_for_secret_share);

    high_resolution_clock::time_point start_share = utility::timer_start();
    secret_share_keys.gen_keys(DS_key, KEY_SIZE_BYTES, constants::SECRET_SHARE_DERIVE_KEY);
    share_time += utility::timer_end(start_share);

    if(!batched)
    {

        for (int i = 0; i < num_of_secret_shares; i++)
        {
            start_share = utility::timer_start();
            sharePT_struct sharePT1 = secret_sharing.gen_share(_secret_num_vec[i], &secret_share_keys, prime_bits_to_bytes);
            share_time += utility::timer_end(start_share);

            // next we prepare the secret share values for storage.
            // In order to make the storage more compact, we group the secret share values
            // into a single double and later the same for the MAC values.

            // the secret share is stored as s_q*p +s_r
            calc_for_store = sharePT1.x_int * _enc_init_params.prime + sharePT1.x_frac;
            os.write(reinterpret_cast<const char*>(&calc_for_store), sizeof(double));

            //cout << "going in to  single mac tag for i: " << i << endl;
            high_resolution_clock::time_point start_mac = utility::timer_start();
            //apply single kmac for each share couple
            K_MAC kmac(_enc_init_params.prime);
            kmac.derive_abcd(hmac_tag, constants::MAC_DERIVE_KEY, i, 1); // derive secret share components
            single_mac_tag tag = mac.single_compact_mac(kmac, 0, sharePT1.x_int, sharePT1.x_frac);
            mac_time += utility::timer_end(start_mac);

            // write the mac tag values
            // the mac values are stored as: z_mskd*p^2 + z_r*p + y_r
            calc_for_store = tag.z_qmskd *prime_square + tag.z_r * _enc_init_params.prime + tag.y_r;
            os_tag.write(reinterpret_cast<const char*>(&calc_for_store), sizeof(double));
        }
    }

    else //batched mode
    {
        vector<double> x_int_for_mac, x_frac_for_mac;
        vector<double> result_vec(_enc_init_params.max_ct_entries, 0.0);

        K_MAC_Batched kmac(_enc_init_params.prime);

        // calculate the amount of required bytes for all keys
        // a_int, a_frac, c_alpha, c_beta and b required the same amount of bytes as the prime.
        // d_alpha and d_beta each require 1 bit, so we can allocate 1 byte for both
        // calculating by bytes maybe space consuming, but is easier for this implementation.
        // future improvement and be to allocate according to number of bits
        ullong num_of_mac_key_bytes = num_of_secret_shares * 2 * prime_bits_to_bytes +  _enc_init_params.max_ct_entries * (prime_bits_to_bytes * 3 + 1);
        SHARE_MAC_KEYS kmac_keys(num_of_mac_key_bytes);

        high_resolution_clock::time_point start_mac = utility::timer_start();

        kmac_keys.gen_keys(MAC_key, KEY_SIZE_BYTES, constants::MAC_DERIVE_KEY);

        mac_time += utility::timer_end(start_mac);

        for (int i = 0; i < num_of_secret_shares; i++)
        {
            high_resolution_clock::time_point start_share = utility::timer_start();
            sharePT_struct sharePT1 = secret_sharing.gen_share(_secret_num_vec[i], &secret_share_keys, prime_bits_to_bytes);
            share_time += utility::timer_end(start_share);

            // next we prepare the secret share values for storage.
            // In order to make the storage more compact, we group the secret share values
            // into a single double and later the same for the MAC values.

            // the secret share is stored as s_q*p +s_r
            calc_for_store = sharePT1.x_int * _enc_init_params.prime + sharePT1.x_frac;
            os.write(reinterpret_cast<const char*>(&calc_for_store), sizeof(double));

            x_int_for_mac.push_back(sharePT1.x_int);
            x_frac_for_mac.push_back(sharePT1.x_frac);

            if ((((i + 1) % _enc_init_params.max_ct_entries) == 0) || ((i + 1) == num_of_secret_shares))
            {
                high_resolution_clock::time_point start_mac = utility::timer_start();
                // calculate x_int * a_int + x_frac * a_frac and then add to the result vector
                kmac.derive_a(&kmac_keys, i - x_int_for_mac.size() + 1, _enc_init_params.max_ct_entries, prime_bits_to_bytes);

                std::transform(x_int_for_mac.begin(), x_int_for_mac.end(), kmac.a_int.begin(), x_int_for_mac.begin(), std::multiplies<double>());
                std::transform(x_frac_for_mac.begin(), x_frac_for_mac.end(), kmac.a_frac.begin(), x_frac_for_mac.begin(), std::multiplies<double>());
                std::transform(x_int_for_mac.begin(), x_int_for_mac.end(), x_frac_for_mac.begin(), x_int_for_mac.begin(), std::plus<double>());
                std::transform(result_vec.begin(), result_vec.end(), x_int_for_mac.begin(), result_vec.begin(), std::plus<double>());

                mac_time += utility::timer_end(start_mac);

                kmac.a_int.clear();
                kmac.a_frac.clear();
                x_int_for_mac.clear();
                x_frac_for_mac.clear();
            }


        }

        start_mac = utility::timer_start();
        kmac.derive_bcd(&kmac_keys, _enc_init_params.max_ct_entries, prime_bits_to_bytes, kmac_keys.keys_iter);
        // add b to the sum of (x_int * a_int + x_frac * a_frac)
        std::transform(result_vec.begin(), result_vec.end(), kmac.b.begin(), result_vec.begin(), std::plus<double>());

        optimized_mac = mac.compact_mac_batched_optimized(kmac, result_vec);
        for(j = 0; j < optimized_mac.mac_part1.size(); j++)
        {
            os_tag.write(reinterpret_cast<const char*>(&optimized_mac.mac_part1[j]), sizeof(double));
        }
        mac_time += utility::timer_end(start_mac);
    }


    performanceMetrics.share = share_time.count();
    performanceMetrics.mac = mac_time.count();

    //converting stream to plain
    plain_x_int_frac = os.str();
    plain_tag = os_tag.str();

    if(batched){
            std::string str(optimized_mac.mac_part2.begin(), optimized_mac.mac_part2.end());
            plain_tag_beta = str;
    }

    // write key and secret share files to AWS bucket
    SDKOptions options;
    //options.loggingOptions.logLevel = Utils::Logging::LogLevel::Debug;
    Aws::InitAPI(options);
    {
        S3Utility s3Utility(awsparams::region);
        std::string DS_key_str(reinterpret_cast<const char *>(DS_key), sizeof(DS_key));
        std::string MAC_key_str(reinterpret_cast<const char *>(MAC_key), sizeof(MAC_key));


        performanceMetrics.upload_shared = saveKeyAndDataToBucket(s3Utility, DS_key_str, plain_x_int_frac, string(CIPHERTEXTS_X_INT_FRAC_DIR), constants::SECRET_SHARE_KEY_FILENAME);
        performanceMetrics.upload_sq = saveKeyAndDataToBucket(s3Utility, MAC_key_str, plain_tag, string(TAGS_SQ_DIR), constants::TAG_SQ_KEY_FILENAME);
        if(batched){

            performanceMetrics.upload_sr = saveKeyAndDataToBucket(s3Utility, MAC_key_str, plain_tag_beta, string(TAGS_SR_DIR), constants::TAG_SR_KEY_FILENAME);
        }
    }
    Aws::ShutdownAPI(options);

    return 1;
}
