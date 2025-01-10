//
// Created by Sapir, Boaz on 08/06/2021.
//

#include "Destination_Server.h"
//#include "../Constants.h"
#include <cpprest/http_client.h>
//#include <iostream>
//#include <fstream>
//#include <sys/stat.h>
#include <aws/core/Aws.h>
#include <aws/core/utils/logging/LogLevel.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/PutObjectRequest.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>


#define PORT 8080

using namespace utility;
using namespace Aws;
using namespace seal;
using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace Aws;

std::ostream& operator<<(std::ostream& out, const DS_performance_metrics& dsPerformanceMetrics){
    return out << dsPerformanceMetrics.wait_for_auxiliary/1000 << "," << dsPerformanceMetrics.receive_from_aux/1000 << "," << dsPerformanceMetrics.push_to_queue/1000
    << "," << dsPerformanceMetrics.deserialize/1000 << "," << dsPerformanceMetrics.deserialize_macs/1000 << "," << dsPerformanceMetrics.derive_b_t/1000 << "," << dsPerformanceMetrics.reconstruct/1000
    << "," << dsPerformanceMetrics.derive_kmacs/1000 << "," << dsPerformanceMetrics.verify/1000 << "," << dsPerformanceMetrics.square_diff/1000
    << "," << dsPerformanceMetrics.total_receive_and_process/1000<< "," << dsPerformanceMetrics.end2end/1000 ;
}

std::string DS_performance_metrics::getHeader(){
    return "wait for auxiliary,receive from aux, push to queue, deserialize, deserialize macs, derive b t,reconstruct, derive kmacs, verify, square diff, total receive and process, end2end_dest";
}

inline shared_ptr<vector<double>> Destination_Server::FillVecByCTSize(std::vector<double>::iterator start, int ct_index){
    std::vector<double> v1(start + ct_index * _enc_init_params.max_ct_entries, start + (ct_index + 1) * _enc_init_params.max_ct_entries);
    return make_shared<vector<double>>(v1);
}

inline shared_ptr<vector<double>> Destination_Server::FillVecByInputSize(std::vector<double>::iterator start, int ct_index){
    std::vector<double> v1(start + ct_index * _enc_init_params.max_ct_entries, start + data_points_num);
    return make_shared<vector<double>>(v1);
}

Destination_Server::Destination_Server(int data_points_num_input, bool batched, string enc_init_params_file, bool squareDiff)
{
    InitEncParams(&_enc_init_params, enc_init_params_file);
    int num_of_bits_prime = (std::log2(_enc_init_params.prime));
        // calc the number of bytes needed for the mac "a" value according to the number of bits in the prime number
        // as all "a" values are in Zp
    prime_bits_to_bytes = std::ceil(num_of_bits_prime / 8.0);
    square_diff = squareDiff;
    data_points_num = data_points_num_input;
    _batched_size = (batched) ? ceil((double)data_points_num / _enc_init_params.max_ct_entries) : 0;
    string DS_file_name = "DS_";
    DS_file_name += std::to_string(_enc_init_params.polyDegree);
    DS_file_name += "_";
    metrics_file = utility::openMetricsFile(data_points_num, DS_file_name);
    metrics_file << DS_performance_metrics::getHeader() << endl;
}

// reads the original secret numbers for validation purposes in test mode
bool Destination_Server::ReadSecret(bool read_secret_from_file)
{
    SDKOptions options;

    // can read the input from a file named "inputs" or from the bucket as saved by the data owner
    if (read_secret_from_file)
    {
        cout << "reading secret values from file" << endl;
        std::fstream inputs_file("inputs", std::ios::in | std::ios::binary);
        if (inputs_file.is_open())
        {
            for (int i=0; i<data_points_num; i++){
                std::string str1;
                char str2[_enc_init_params.float_precision_for_test+1];
                inputs_file.read(str2, _enc_init_params.float_precision_for_test);
                str2[_enc_init_params.float_precision_for_test] = '\0';
                _secret_vec.push_back(std::atof(str2));
            }
        }
        else throw std::runtime_error("Unable to open file 'inputs'");
    }
    else
    {
        cout << "reading secret values from s3 bucket" << endl;
        InitAPI(options);
        {
            S3Utility s3_utility(awsparams::region);
            char* buf = new char[data_points_num*_enc_init_params.float_precision_for_test];
            if (buf == NULL){
                std::cerr << "Error: Cannot allocate buffer" << endl;
                return false;
            }

            if (s3_utility.load_from_bucket("inputs", awsparams::bucket_name, data_points_num*_enc_init_params.float_precision_for_test, buf)){
                for (int i=0; i<data_points_num; i++){
                    std::string str1;
                    char str2[_enc_init_params.float_precision_for_test+1];
                    str1.append(buf + i*_enc_init_params.float_precision_for_test, _enc_init_params.float_precision_for_test );
                    //cout << "Input is "  << str1 << endl;
                    _secret_vec.push_back(std::atof(str1.c_str())); //inserting to vector as double
                }
                delete buf;
            }
            else {
                delete buf;
                throw std::runtime_error("Unable to get file 'inputs' from S3");
            }
        }
        ShutdownAPI(options);
    }

    return true;
}

bool uploadKeyToBucket(Aws::S3::Model::PutObjectRequest request, Aws::S3::S3Client s3_client, std::string key_str)
{
        std::shared_ptr <Aws::IOStream> input_data =
                Aws::MakeShared<Aws::StringStream>("SampleAllocationTag", key_str,
                                                   std::ios_base::in | std::ios_base::binary);

        request.SetBody(input_data);
        cout << "Uploading Public Key" << endl;
        Aws::S3::Model::PutObjectOutcome outcome =
                s3_client.PutObject(request);

        if (outcome.IsSuccess()) {

            std::cout << "Added key to bucket '"
                      << awsparams::bucket_name << "'." << endl;
            //return true;
        } else {
            std::cout << "Error: PutObject: " <<
                      outcome.GetError().GetMessage() << std::endl;

            return false;
        }

        return true;
}

// read or generate homomorphic encryption keys and base key for secret share reconstruction
bool Destination_Server::GetEncryptionParams(bool read_keys_from_file, bool read_keys_from_s3, bool with_mac)
{
    SDKOptions options;
    Servers_Protocol srvProtocol;
    EncryptionParameters parms;
    seal::PublicKey pk_fhe;
    SecretKey sk_fhe;
    bool gen_new_keys = !(read_keys_from_file || read_keys_from_s3); // if reading keys from a file or s3 was not selected, generate new ones
    int polyDegree = _enc_init_params.polyDegree;
    vector<int> bit_sizes = _enc_init_params.bit_sizes;
    string pk_object_name = string("pk-fhe-") + std::to_string(_enc_init_params.polyDegree);
    string sk_object_name = string("sk-fhe-") + std::to_string(_enc_init_params.polyDegree);
    string parms_object_name  = string("seal-params-") + std::to_string(_enc_init_params.polyDegree);

    if(read_keys_from_file)
    {
        // Get the base value for derivation of b and t from the file
        std::fstream ds_key_file("key_DS.txt", std::ios::in | std::ios::binary);
        if (ds_key_file.is_open()){
            ds_key_file.read(_DS_key_ch, KEY_SIZE_BYTES);
        }
        else{
            throw std::runtime_error("Unable to open file 'key_DS.txt'");
        }

        if(with_mac){

            std::fstream sq_key_file("key_sq.txt", std::ios::in | std::ios::binary);
            if (sq_key_file.is_open()){
                sq_key_file.read(_SQ_key_ch, KEY_SIZE_BYTES);
            }
            else{
                throw std::runtime_error("Unable to open file 'key_sq.txt'");
            }

            std::fstream sr_key_file("key_sr.txt", std::ios::in | std::ios::binary);
            if (sr_key_file.is_open()){
                sr_key_file.read(_SR_key_ch, KEY_SIZE_BYTES);
            }
            else{
                throw std::runtime_error("Unable to open file 'key_sr.txt'");
            }
        }

        std::fstream file_parms_fhe2(parms_object_name, std::ios::in | std::ios::binary);
        if (file_parms_fhe2.is_open())
        {
            parms.load(file_parms_fhe2);
            file_parms_fhe2.close();
        }
        else throw std::runtime_error("Unable to open file seal-params");

        _seal = srvProtocol.gen_seal_params(parms.poly_modulus_degree(), parms.coeff_modulus(), _enc_init_params.scale);
        cout << " generated seal params" << endl;

        //loading sk
        std::fstream file_sk_fhe2(sk_object_name, std::ios::in | std::ios::binary);
        if (file_sk_fhe2.is_open())
        {
            sk_fhe.load(_seal->context_ptr, file_sk_fhe2);
            file_sk_fhe2.close();
        }
        else throw std::runtime_error("Unable to open file sk-fhe");

        _seal->decryptor_ptr = make_shared<Decryptor>(_seal->context_ptr, sk_fhe);

        //loading pk
        std::fstream file_pk_fhe2(pk_object_name, std::ios::in | std::ios::binary);
        if (file_pk_fhe2.is_open())
        {
            pk_fhe.load(_seal->context_ptr, file_pk_fhe2);
            file_pk_fhe2.close();
        }
        else throw std::runtime_error("Unable to open file pk-fhe");

        _seal->encryptor_ptr = make_shared<Encryptor>(_seal->context_ptr, pk_fhe);
    }
    else
    {
        InitAPI(options);
        {
            S3Utility s3_utility(awsparams::region);
            Aws::Client::ClientConfiguration config;
            config.region = awsparams::region;
            Aws::S3::S3Client s3_client(config);


            // Get the base value for derivation of b and t from the bucket
            if (!s3_utility.load_from_bucket("key_DS.txt", awsparams::bucket_name, KEY_SIZE_BYTES, _DS_key_ch)) {
                throw std::runtime_error("Unable to get DS key from bucket");
            }

            if(with_mac){
                if (!s3_utility.load_from_bucket("key_sq.txt", awsparams::bucket_name, KEY_SIZE_BYTES, _SQ_key_ch)) {
                    throw std::runtime_error("Unable to get sq key from bucket");
                }
                 if (!s3_utility.load_from_bucket("key_sr.txt", awsparams::bucket_name, KEY_SIZE_BYTES, _SR_key_ch)) {
                    throw std::runtime_error("Unable to get sr key from bucket");
                }
            }

            // generate new security keys
            if (gen_new_keys)
            {
                _seal = srvProtocol.gen_seal_params(polyDegree,
                                                   bit_sizes, _enc_init_params.scale); //initialize SEAL parameters - derived from parent class
                Aws::S3::Model::PutObjectRequest request;
                request.SetBucket(awsparams::bucket_name);

                // Save Public Key
                request.SetKey(pk_object_name);
                std::stringstream pk_str;
                _seal->pk_ptr->save(pk_str);
                uploadKeyToBucket(request, s3_client, pk_str.str());

                // Save Secret Key
                request.SetKey(sk_object_name);
                std::stringstream sk_str;
                _seal->sk_ptr->save(sk_str);
                uploadKeyToBucket(request, s3_client, sk_str.str());

                // Save Encryption Parameters
                parms = _seal->context_ptr.key_context_data()->parms();
                request.SetKey(parms_object_name);
                std::stringstream parms_str;
                parms.save(parms_str);
                uploadKeyToBucket(request, s3_client, parms_str.str());
            }
            else if (read_keys_from_s3)
            {
                if (!utility::GetEncryptionParamsFromBucket(parms_object_name, awsparams::bucket_name,
                                                            awsparams::region, parms)) {
                    std::cerr << "Failed to get Encryption Params";
                    return false;
                }
                _seal = srvProtocol.gen_seal_params(parms.poly_modulus_degree(), parms.coeff_modulus(), _enc_init_params.scale);
                cout << " generated seal params" << endl;
                if (!utility::GetPublicKeyFromBucket(pk_object_name, awsparams::bucket_name, awsparams::region,
                                                     _seal->context_ptr, pk_fhe)) {
                    std::cerr << "Failed to get public key";
                    return false;
                }
                _seal->encryptor_ptr = make_shared<Encryptor>(_seal->context_ptr, pk_fhe);

                if (!utility::GetSecretKeyFromBucket(sk_object_name, awsparams::bucket_name, awsparams::region,
                                                     _seal->context_ptr, sk_fhe)) {
                    std::cerr << "Failed to get secret key";
                    return false;
                }
                _seal->decryptor_ptr = make_shared<Decryptor>(_seal->context_ptr, sk_fhe);
            }
        }
        ShutdownAPI(options);
    }

    // generate hmac for secret share and mac
    //hmac = CryptoPP::HMAC<CryptoPP::SHA256>((const unsigned char*)_DS_key, KEY_SIZE_BYTES);

    if (with_mac && (_batched_size == 0))
    {
        hmac_sq = CryptoPP::HMAC<CryptoPP::SHA256>((const unsigned char*)_SQ_key_ch, KEY_SIZE_BYTES);
        hmac_sr = CryptoPP::HMAC<CryptoPP::SHA256>((const unsigned char*)_SR_key_ch, KEY_SIZE_BYTES);
    }
    return true;
}


void Destination_Server::VerifyAndReconstruct(vector<std::string> str_vec, bool with_mac, DS_performance_metrics *performanceMetrics)
{
    Secret_Sharing secret_sharing(_enc_init_params);
    MAC mac(_enc_init_params);
    K_MAC kmac_sq(_enc_init_params.prime);

    K_MAC_Batched kmac_batched(_enc_init_params.prime);
    int total_if_ct_full, total_before_curr_ct, ct_num_of_data_points;
    int ct_index = std::stoi(str_vec[CT_IDX]);
    key_mac kmac_sq_vec, kmac_sr_vec;
    Ciphertext ct_int, ct_frac, ct_int_const, ct_frac_const, ct_t_r, ct_zqmskd, ct_alpha_int, ct_beta_int;//, ct_t_sr, ct_zqmskd_sr;
    vector<double> kmac_sq_a_int_vec, kmac_sq_a_frac_vec, kmac_sq_b_vec, kmac_sq_c_vec, kmac_sq_d_vec;

    vector<double> cleartext_vec;
    vector<double> cleartext_for_cipher_vec;

    // calculate the number of data points in the ciphertext
    // In most cases the number of datapoints in the ciphertext will be the maximal
    // encoded amount. However, if the last ciphertext is not full,
    // we need to calculate how many points it contains.

    // assuming all ciphertexts up to now contain the maximum supported amount, this will be the total number of packed values
    total_if_ct_full = (ct_index + 1) * _enc_init_params.max_ct_entries;

    // the total amount of num points before the current ciphertext
    total_before_curr_ct = ct_index * _enc_init_params.max_ct_entries;

    // this will be the current CT amount of datapoints
    ct_num_of_data_points = (total_if_ct_full > data_points_num) ? data_points_num - total_before_curr_ct : _enc_init_params.max_ct_entries;

    for (int i = 0; i < ct_num_of_data_points; i++)
    {
        // calculate the location of the current ciphertext index inside the full datapoint list
        int index_base = ct_index * _enc_init_params.max_ct_entries + i;

        high_resolution_clock::time_point start_derive = utility::timer_start();
        sharePT_struct shared_struct = secret_sharing.Derive_b_t(&_secret_share_keys, prime_bits_to_bytes);
        performanceMetrics->derive_b_t += utility::timer_end(start_derive).count();

        high_resolution_clock::time_point start_prepare_vector = utility::timer_start();
        // this is: (-1)^b * (-b)
        // note that the outcome of this calculation will be the same as the value of b
        double cleartext_pt1  = shared_struct.b;
        // this is the cleartext calculation value
        double cleartext_calc_val = _enc_init_params.prime * cleartext_pt1 - shared_struct.t;
        cleartext_vec.push_back(cleartext_calc_val);

        // this is the cleartext part of the ciphertext calculation: p * (-1)^b
        double minus_one_to_the_b = (shared_struct.b == 1) ? -1 : 1;
        cleartext_for_cipher_vec.push_back(_enc_init_params.prime * minus_one_to_the_b);

        performanceMetrics->reconstruct += utility::timer_end(start_prepare_vector).count();

    }

    if (with_mac)
    {
        int index_base = ct_index * _enc_init_params.max_ct_entries;

        high_resolution_clock::time_point start_derive_kmac = utility::timer_start();
        if (_batched_size == 0)
        {
            kmac_sq = mac.Derive_compact_kmac_unbatched_single(hmac_sq, index_base, ct_num_of_data_points);
        }
        else
        {
            // for batched mac, derive the "a" values for x_int and x_frac
            kmac_batched.derive_a(&_kmac_keys, index_base, ct_num_of_data_points, prime_bits_to_bytes);
        }

        performanceMetrics->derive_kmacs += utility::timer_end(start_derive_kmac).count();
    }

    // de-serialize and reconstruct the secret share values
    high_resolution_clock::time_point start_deserialize = utility::timer_start();

    utility::deserialize_fhe(str_vec[X_INT_IDX].c_str(), std::stol(str_vec[X_INT_SIZE]), ct_int, _seal->context_ptr);
    utility::deserialize_fhe(str_vec[X_FRAC_IDX].c_str(), std::stol(str_vec[X_FRAC_SIZE]), ct_frac, _seal->context_ptr);

    performanceMetrics->deserialize += utility::timer_end(start_deserialize).count();

    ct_int_const = ct_int; //static copy since x_int is to be edited during reconstruct
    ct_frac_const = ct_frac; //static copy since x_frac is to be edited during reconstruct

    high_resolution_clock::time_point start_actual_reconstruct = utility::timer_start();
    const Ciphertext x_final_CT = secret_sharing.Rec_CT(cleartext_vec, cleartext_for_cipher_vec, ct_int, ct_frac, _seal);
    nanoseconds reconstruct_time = utility::timer_end(start_actual_reconstruct);
    performanceMetrics->reconstruct += reconstruct_time.count();

    reconstructed_FHE_CT.push_back(x_final_CT);

    if (with_mac)
    {
        if (_batched_size == 0) //unbatched mac verification
        {
            mac_tag_ct macTagCT_sr, macTagCT_sq;

            high_resolution_clock::time_point start_deserialize_mac = utility::timer_start();
            utility::deserialize_fhe(str_vec[SQ_TR_IDX].c_str(), std::stol(str_vec[SQ_TR_SIZE]), ct_t_r, _seal->context_ptr);
            utility::deserialize_fhe(str_vec[SQ_ZQMSKD_IDX].c_str(), std::stol(str_vec[SQ_ZQMSKD_SIZE]), ct_zqmskd, _seal->context_ptr);
            performanceMetrics->deserialize_macs += utility::timer_end(start_deserialize_mac).count();

            macTagCT_sq.t_r_ct = make_shared<Ciphertext>(ct_t_r);
            macTagCT_sq.z_qmskd_ct = make_shared<Ciphertext>(ct_zqmskd);

            const Ciphertext diff_SQ_CT = mac.compact_unbatched_VerifyHE(_seal, kmac_sq, ct_int_const, ct_frac_const, macTagCT_sq, square_diff, ct_num_of_data_points, performanceMetrics);

            diff_SQ_FHE_CT.push_back(diff_SQ_CT);
        }
        else // batched mac
        {
            Ciphertext ax_ct = mac.verifyHE_batched_y(_seal, kmac_batched, ct_int_const, ct_frac_const, performanceMetrics);
            // this is adds a_int*x_int + a_frac*x_frac values calculated earlier to all the same values from the previous ciphertexts
            high_resolution_clock::time_point start_verify = utility::timer_start();
            _seal->evaluator_ptr->mod_switch_to_inplace(batched_y_ct, ax_ct.parms_id());
            _seal->evaluator_ptr->add_inplace(batched_y_ct, ax_ct);
            performanceMetrics->verify += utility::timer_end(start_verify).count();

            // if the queue also contains the y_tag data, extract that too
            if (str_vec.size() - 1 > X_FRAC_IDX)
            {
                int bcd_key_index = data_points_num * 2 * prime_bits_to_bytes;
                high_resolution_clock::time_point start_derive_kmac = utility::timer_start();
                kmac_batched.derive_bcd(&_kmac_keys, ct_num_of_data_points, prime_bits_to_bytes, bcd_key_index);
                performanceMetrics->derive_kmacs += utility::timer_end(start_derive_kmac).count();

                high_resolution_clock::time_point start_deserialize_mac = utility::timer_start();
                utility::deserialize_fhe(str_vec[BATCHED_TR_IDX].c_str(), std::stol(str_vec[BATCHED_TR_SIZE]), ct_t_r, _seal->context_ptr);
                utility::deserialize_fhe(str_vec[BATCHED_ALPHA_INT_IDX].c_str(), std::stol(str_vec[BATCHED_ALPHA_INT_SIZE]), ct_alpha_int, _seal->context_ptr);
                utility::deserialize_fhe(str_vec[BATCHED_BETA_INT_IDX].c_str(), std::stol(str_vec[BATCHED_BETA_INT_SIZE]), ct_beta_int, _seal->context_ptr);
                performanceMetrics->deserialize_macs += utility::timer_end(start_deserialize_mac).count();

                batched_y_tag_ct = mac.verifyHE_batched_y_tag(_seal, ct_num_of_data_points, kmac_batched, ct_t_r, ct_alpha_int, ct_beta_int, performanceMetrics);
            }

        }
    }

}


void Destination_Server::ProcessCt(DS_performance_metrics* performanceMetrics, bool with_mac)
{
    while (this->total_num_of_unprocessed_ct > 0)
    {
        if (!this->_ct_queue.empty())
        {
            std::unique_lock<std::mutex> lock(_mutex);

            vector<string> ct_vec = _ct_queue.front();
            _ct_queue.pop();
            //cout << "Remaining unprocessed: " << total_num_of_unprocessed_ct << endl;
            this->total_num_of_unprocessed_ct--;
            lock.unlock();
            VerifyAndReconstruct(ct_vec, with_mac, performanceMetrics);
        }

        usleep(50);
    }

}


void Destination_Server::RequestAndParseDataFromAux(int repeatTimes, string server_ip, bool with_mac, bool test_mode, bool read_secret_from_file)
{
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    int buffer_size = sizeof(ullong);
    char str_size_buffer[buffer_size + 1] = {0};
    vector<string> ct_vec;

    //byte _DS_key[KEY_SIZE_BYTES];
    //byte _SQ_key[KEY_SIZE_BYTES];
    //byte _SR_key[KEY_SIZE_BYTES];

    // initialize mac ciphertexts for batched verification
    if (_batched_size > 0)
    {
        vector<double> zero_vec(_enc_init_params.max_ct_entries, 0);
        Plaintext zero_pt;
        _seal->encoder_ptr->encode(zero_vec, _enc_init_params.scale, zero_pt);
        _seal->encryptor_ptr->encrypt(zero_pt, batched_y_ct);
        _seal->encryptor_ptr->encrypt(zero_pt, batched_y_tag_ct);
    }


    for (int i = 0; i < repeatTimes; i++)
    {
        int index = 0;
        long ct_count = 0;
        total_num_of_unprocessed_ct = (data_points_num / _enc_init_params.max_ct_entries) + (((data_points_num % _enc_init_params.max_ct_entries) > 0) ? 1 : 0);
        DS_performance_metrics performanceMetrics;
        std::thread processingThread(&Destination_Server::ProcessCt, this, &performanceMetrics, with_mac);

        high_resolution_clock::time_point end2end = utility::timer_start();
        int bytes_for_secret_share = data_points_num * (prime_bits_to_bytes + 1);
        _secret_share_keys = SHARE_MAC_KEYS(bytes_for_secret_share);

        // initialize secret share keys using hkdf
        high_resolution_clock::time_point start_derive = utility::timer_start();
        _secret_share_keys.gen_keys((byte*)_DS_key_ch, KEY_SIZE_BYTES, constants::SECRET_SHARE_DERIVE_KEY);
        long long the_time = utility::timer_end(start_derive).count();
        performanceMetrics.derive_b_t += utility::timer_end(start_derive).count();

        if (_batched_size > 0) // initialize mac keys for batched mode using hkdf
        {
            high_resolution_clock::time_point start_derive_kmac = utility::timer_start();
            // calculate the amount of required bytes for all keys
            // a_int, a_frac, c_alpha, c_beta and b required the same amount of bytes as the prime.
            // d_alpha and d_beta each require 1 bit, so we can allocate 1 byte for both
            // calculating by bytes maybe space consuming, but is easier for this implementation.
            // future improvement and be to allocate according to number of bits
            int num_of_mac_key_bytes = data_points_num * 2 * prime_bits_to_bytes +  _enc_init_params.max_ct_entries * (prime_bits_to_bytes * 3 + 1);
            _kmac_keys = SHARE_MAC_KEYS(num_of_mac_key_bytes);

            _kmac_keys.gen_keys((byte*)_SQ_key_ch, KEY_SIZE_BYTES, constants::MAC_DERIVE_KEY);
            performanceMetrics.derive_kmacs += utility::timer_end(start_derive_kmac).count();
        }

        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            perror("Socket creation error");
            exit(1);
        }

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(PORT);

        // Convert IPv4 address from text to binary form
        if (inet_pton(AF_INET, server_ip.c_str(), &serv_addr.sin_addr) <= 0)
        {
            perror("Invalid IP address\n");
            exit(1);
        }

        high_resolution_clock::time_point start_send_request = utility::timer_start();

        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            perror("Connection Failed\n");
            exit(1);
        }

        performanceMetrics.wait_for_auxiliary = utility::timer_end(start_send_request).count();

        std::cout << "Started receiving data from Aux" << endl;
        high_resolution_clock::time_point total_receive_and_process = utility::timer_start();


        // calculate the amount of expected num of ciphertexts to form a set of secret share + mac
        // in case of no_mac, only the number of secret share ciphertexts is expected
        // in case of unbatched mac, there will be mac+secret share number of ciphertexts
        // in case of batched mac, the number of mac ciphertexts is expected to be less than the amount of secret share at some point
        int expected_num_of_ct = (with_mac) ? ((_batched_size > 0) ? MAX_IDX_WITH_BATCHED_MAC : MAX_IDX_WITH_UNBATCHED_MAC) : MAX_IDX_WITHOUT_MAC;

        // read the size of the serialized string from the server
        while ((valread = read(sock, str_size_buffer, buffer_size)) > 0)
        {
            int curr_ct_count;
            high_resolution_clock::time_point receive_from_aux = utility::timer_start();
            // prepare a buffer according to the read size
            ullong ser_str_size = atoll(str_size_buffer);

            char ser_buffer[ser_str_size + 1] = {0};
            char *pSerBuffer = ser_buffer;
            bzero(ser_buffer, ser_str_size + 1);

            // here we build a queue of string vectors
            // the format of each vector is as following:
            // ciphertext index (according to the order in which it's received from the Aux
            // secret share int serialized string size
            // secret share int serialized string
            // secret share frac serialized string size
            // secret share frac serialized string
            // and in the same way, the mac serialized ciphertexts
            // in total we should expect 4 ciphertexts when mac is enabled in unbatched mode
            // in batched mode we expect 5 ciphertexts while transmitting mac data and 2 ciphertexts once all mac ciphertexts have been sent

            ullong remaining = ser_str_size;
             // cout << "Receiving size of: " << remaining << endl;
            valread = 0;

            int retries = 20;
            while (remaining > 0)
            {
                if ((valread = read(sock, pSerBuffer, ser_str_size)) <= 0)
                {
                    if (retries == 0)
                    {
                              perror("Failed to read serialized string\n");
                              exit(1);
                    }
                    cout << "Failed to read serealized string, but don't worry, we're retrying. valread is: " << valread << " remaining retries: " << retries << endl;
                    retries--;
                }
                remaining -= valread;
                pSerBuffer += valread;
            }

            performanceMetrics.receive_from_aux += utility::timer_end(receive_from_aux).count();
            // insert the vector size
            string size_of_ct(str_size_buffer);
            ct_vec.push_back(size_of_ct);
            string ser_str(ser_buffer, ser_str_size);

            ct_vec.push_back(ser_str);

            ct_count++;
            curr_ct_count++;

            if (curr_ct_count ==  expected_num_of_ct)
            {
                high_resolution_clock::time_point push_to_queue = utility::timer_start();
                // insert the ciphertext index
                ct_vec.insert(ct_vec.begin(), std::to_string(index));
                // acquire a lock
                std::unique_lock<std::mutex> lock(_mutex);
                // update the queue
                _ct_queue.push(ct_vec);
                // unlock the mutex
                lock.unlock();
                // clear the vector for the next entry
                ct_vec.clear();
                curr_ct_count = 0;
                index++;
                // in batched mac, the first set of ciphertexts include the mac details. the rest don't.
                if (_batched_size > 0)
                {
                    expected_num_of_ct = MAX_IDX_WITHOUT_MAC;
                }

                performanceMetrics.push_to_queue += utility::timer_end(push_to_queue).count();

            }

            bzero(str_size_buffer, buffer_size);
        }


        processingThread.join();

        // for batched mac, need to perform the diff after completion of all threads
        if (_batched_size > 0)
        {
            Ciphertext diff_ct;

            high_resolution_clock::time_point start_verify = utility::timer_start();
            _seal->evaluator_ptr->sub(batched_y_ct, batched_y_tag_ct, diff_ct);
            diff_SQ_FHE_CT.push_back(diff_ct);
            performanceMetrics.verify += utility::timer_end(start_verify).count();
        }

        performanceMetrics.total_receive_and_process = utility::timer_end(total_receive_and_process).count();
        performanceMetrics.end2end = utility::timer_end(end2end).count();

        std::cout << "Done receiving data from Aux" << endl << endl;

        metrics_file << performanceMetrics << endl;

        if (test_mode)
        {
            VerifyOutput(read_secret_from_file, with_mac);
        }
    }

    metrics_file.close();
}

void Destination_Server::VerifyOutput(bool read_secret_from_file, bool with_mac)
{
    ReadSecret(read_secret_from_file);

    tests::is_correct_secret_sharing(make_shared<vector<Ciphertext>>(reconstructed_FHE_CT), _seal, _secret_vec, data_points_num, _enc_init_params.max_ct_entries);

    if(with_mac){
        tests::is_MAC_HE_valid(_seal, make_shared<vector<Ciphertext>>(diff_SQ_FHE_CT), data_points_num, _enc_init_params.max_ct_entries, "SQ", true); //test for sq
        //tests::is_MAC_HE_valid(_seal, make_shared<vector<Ciphertext>>(diff_SR_FHE_CT), data_points_num, _enc_init_params.max_ct_entries, "SR", true); //test for sr - for old version
    }
}

