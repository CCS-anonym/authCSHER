
#include "Test_Protocol.h"
#include "../Utility.h"
#include <aws/core/Aws.h>
#include <aws/core/utils/logging/LogLevel.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/PutObjectRequest.h>
#include <iomanip>
#include <cryptopp/osrng.h>

using namespace Aws;


std::ostream& operator<<(std::ostream& out, const TP_performance_metrics& tpPerformanceMetrics) {
    return out << tpPerformanceMetrics.encode/1000 <<","<< tpPerformanceMetrics.encrypt/1000 <<","<< tpPerformanceMetrics.serialize/1000<<
    ","<< tpPerformanceMetrics.store/1000 <<","<< tpPerformanceMetrics.load/1000 << ","<< tpPerformanceMetrics.deserialize/1000 <<
    "," <<tpPerformanceMetrics.hmac/1000 <<"," <<tpPerformanceMetrics.verify/1000 <<
    ","<<tpPerformanceMetrics.encode_no_mac/1000 <<","<< tpPerformanceMetrics.encrypt_no_mac/1000 <<","<< tpPerformanceMetrics.serialize_no_mac/1000<<
    ","<< tpPerformanceMetrics.store_no_mac/1000 <<","<< tpPerformanceMetrics.load_no_mac/1000<< ","<< tpPerformanceMetrics.deserialize_no_mac/1000<<
    ","<< tpPerformanceMetrics.hkdf/1000<< ","<< tpPerformanceMetrics.decode_no_mac/1000<<","<< tpPerformanceMetrics.decrypt_no_mac/1000;}

std::string TP_performance_metrics::getHeader(){
    return "encode, encrypt, serialize, store, load, deserialize, hmac, verify, encode_no_mac, encrypt_no_mac, serialize_no_mac, store_no_mac, load_no_mac, deserialize_no_mac, hkdf, decode_no_mac, decrypt_no_mac";
}

Test_Protocol::Test_Protocol(string enc_init_params_file)
{
    InitEncParams(&_enc_init_params, enc_init_params_file);
}


void Test_Protocol::test_save_time(void)
{
    char c = 'a';

    int repetitions = 10;
    long long size_struct[] = {1, 8192, 16252928};
    std::string str_to_save;
    int buf_size;

    SDKOptions options;
    Aws::InitAPI(options);
    {
        S3Utility s3Utility(awsparams::region);

        for(int buf_idx = 0; buf_idx < sizeof(size_struct) / sizeof(long long); buf_idx++)
        {
            buf_size = size_struct[buf_idx];
            str_to_save = std::string(buf_size, c);
            std::string file_name = "save_test";

            long long share_time = 0;
            long long load_time = 0;

            char *single_buf = new char [buf_size];

            for (int i = 0; i < repetitions; i++)
            {

              high_resolution_clock::time_point start_save = utility::timer_start();

              s3Utility.save_to_bucket(file_name, awsparams::bucket_name, str_to_save);

              share_time += utility::timer_end(start_save).count();

              high_resolution_clock::time_point start_load = utility::timer_start();

              s3Utility.load_from_bucket(file_name.c_str(), awsparams::bucket_name,
                                        buf_size, single_buf);

              load_time += utility::timer_end(start_load).count();

            }

            delete single_buf;

            cout << "save time for string of length " << str_to_save.length() << " bytes: " << (share_time/repetitions)/1000 << "us" << endl;
            cout << "load time for string of length " << str_to_save.length() << " bytes: " << (load_time/repetitions)/1000 << "us" << endl;
        }

    }
    Aws::ShutdownAPI(options);

}



shared_ptr<seal_struct> Test_Protocol::set_seal_struct(){

    Servers_Protocol srvProtocol;
    shared_ptr<seal_struct> seal = srvProtocol.gen_seal_params(_enc_init_params.polyDegree, _enc_init_params.bit_sizes, _enc_init_params.scale);
    return seal;
}

void Test_Protocol::test_storage_batched_sim()
{
    // simulate the storage of secret share and 3 mac repetitions together.
    // this is used to simulate the storage speed for 16384, 98304 and 507904 items.

    int input_size[] = {16384, 98304, 507904};
    int bytes_per_secret_share = 8; // single double per secret share
    int total_mac_bytes = 3 * 8192 * 9;  // 8192 mac items. each mac item contains a double and a byte
    int num_of_repetitions = 10;
    nanoseconds store_time;
    ullong total_store_time_usecs = 0;

    // for random generation
    const char charSet[] = "0123456789abcdef";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, 15);


    int total_size = 0;

    for (int i = 0; i < sizeof(input_size)/sizeof(int); i++)
    {
        total_size = input_size[i] * bytes_per_secret_share + total_mac_bytes;
        // generate random string;
        std::string random_str(total_size, '\0');
        for (int j = 0; j < total_size; j++)
        {
            random_str[j] = charSet[distribution(generator)];
        }

        cout << "Testing " << num_of_repetitions << " repetitions for input of size: " << input_size[i] << ". Saving " << random_str.length() << " bytes to bucket" << endl;

        total_store_time_usecs = 0;

        for (int j = 0; j < num_of_repetitions; j++)
        {
            SDKOptions options;
            Aws::InitAPI(options);
            {
                S3Utility s3_utility(awsparams::region);

                high_resolution_clock::time_point start_store = utility::timer_start();
                s3_utility.save_to_bucket("save_test", awsparams::bucket_name, random_str);
                nanoseconds store_time = utility::timer_end(start_store);
                total_store_time_usecs += store_time.count() / 1000;

            }

        }

        cout << std::setprecision(32) << "Average store time: " << total_store_time_usecs / (double)num_of_repetitions << " micro seconds" <<  endl;
    }

}


void Test_Protocol::test_storage_unbatched(ullong input_size, shared_ptr<seal_struct> seal, bool with_mac, TP_performance_metrics& performanceMetrics){

    CryptoPP::AutoSeededRandomPool prng;
    byte key[KEY_SIZE_BYTES];
    prng.GenerateBlock(key, KEY_SIZE_BYTES);

    vector<double> input_vec;
    for (int i = 0; i < input_size; i++) {
            input_vec.push_back(utility::x_gen(0.0, 1.0)); //generating random input data
        }

    vector <Ciphertext> x_FHE;
    vector <Plaintext> x_pt;

    //zero local timers before each run, adding them to global timers.
    nanoseconds encode_time = nanoseconds::zero();
    nanoseconds encrypt_time =nanoseconds::zero();
    nanoseconds serialize_time =nanoseconds::zero();
    nanoseconds mac_time = nanoseconds::zero();
    nanoseconds deserialize_time =nanoseconds::zero();
    nanoseconds verify_time =nanoseconds::zero();

    for (int k = 0; k < input_size; k++){
        Plaintext plain_x;
        high_resolution_clock::time_point start_encode = utility::timer_start();
        seal->encoder_ptr->encode(input_vec[k], _enc_init_params.scale, plain_x);
        encode_time += utility::timer_end(start_encode);
        x_pt.push_back(plain_x);
    }
    performanceMetrics.encode = encode_time.count();

    for (int k = 0; k < input_size; k++){
        Ciphertext x_FHE_tmp;
        high_resolution_clock::time_point start_encrypt = utility::timer_start();
        seal->encryptor_ptr->encrypt(x_pt[k], x_FHE_tmp);
        encrypt_time += utility::timer_end(start_encrypt);
        x_FHE.push_back(x_FHE_tmp);
    }
    performanceMetrics.encrypt = encrypt_time.count();

    string str1; //string for ser ct
    string str2; //for over 1024

    for (int k = 0; k < input_size; k++){
        if(!with_mac){
            high_resolution_clock::time_point start_serialize = utility::timer_start();
            str1.append(utility::serialize_fhe(x_FHE[k]));
            serialize_time += utility::timer_end(start_serialize);
        }

        else{
            high_resolution_clock::time_point start_serialize = utility::timer_start();
            std::string cur_string = utility::serialize_fhe(x_FHE[k]);
            serialize_time += utility::timer_end(start_serialize);
            string cur_mac; //setting empty string for mac

            try
            {
                HMAC< SHA256 > hmac(key, KEY_SIZE_BYTES);

                high_resolution_clock::time_point start_mac = utility::timer_start();
                StringSource ss2(cur_string, true,
                    new HashFilter(hmac,
                        new StringSink(cur_mac)
                    ) // HashFilter
                ); // StringSource
                mac_time += utility::timer_end(start_mac);

                if( cur_mac.size()!= KEY_SIZE_BYTES) { //HMAC with SHA256 is always 256 bits, 32 bytes.
                    cout << " mac failed, mac tag size: " <<cur_mac.size() << endl;
                }
            }
            catch(const CryptoPP::Exception& e)
            {
                std::cerr << e.what() << endl;
                exit(1);
            }
            if(k<(input_size/2))
            {
                str1.append(cur_string);
                str1.append(cur_mac);
            }
            else{
                str2.append(cur_string);
                str2.append(cur_mac);
            }
        }
    }
    performanceMetrics.hmac = mac_time.count();
    performanceMetrics.serialize = serialize_time.count();

    //saving each ct size for decoding later
    vector<long> ct_size_vec;
    for (int k = 0; k < input_size; k++){
            if(!with_mac){
                ct_size_vec.push_back(utility::serialize_fhe(x_FHE[k]).size());

            }
        else{
                ct_size_vec.push_back(utility::serialize_fhe(x_FHE[k]).size()+KEY_SIZE_BYTES);
        }
    }

    //std::cout << "3 - serialized" << endl;

    SDKOptions options;
    Aws::InitAPI(options);
    {
        S3Utility s3_utility(awsparams::region);

        high_resolution_clock::time_point start_store = utility::timer_start();
        s3_utility.save_to_bucket("fhe_inputs", awsparams::bucket_name, str1);
        if(with_mac){
            s3_utility.save_to_bucket("fhe_inputs2", awsparams::bucket_name, str2);
        }
        nanoseconds store_time = utility::timer_end(start_store);
        performanceMetrics.store = store_time.count();
        //cout << "Time to STORE data " << store_time.count() << endl;
        //std::cout << "4 - saved to bucket" << endl;
    }


    long ct_size = str1.size();
    cout <<"ct_size with hmac is: "<<ct_size<<endl;
    //allocating buffer for FHE load
    char* buf = new char[ct_size];
    if (buf == NULL){
        std::cerr << "Error: Cannot allocate buffer" << endl;
        return;
    }

    long ct_size2 = str2.size();
    char* buf2;
    if(with_mac){
        cout <<"ct2_size with hmac is: "<<ct_size2<<endl;
        buf2 = new char[ct_size2];
        if (buf2 == NULL){
        std::cerr << "Error: Cannot allocate buffer2" << endl;
        return;
        }
    }

    S3Utility s3utility(awsparams::region);

    //setting timer and loading FHE block
    high_resolution_clock::time_point start_load = utility::timer_start();
    s3utility.load_from_bucket("fhe_inputs", awsparams::bucket_name,  ct_size, buf);
    if(with_mac){
        s3utility.load_from_bucket("fhe_inputs2", awsparams::bucket_name,  ct_size2, buf2);
        //cout << "loaded second input file" << endl;
    }
    nanoseconds load_time = utility::timer_end(start_load);
    performanceMetrics.load = load_time.count();
    //cout << "Time to load data " << load_time.count() << endl;

    int idx = 0; int idx2 = 0;
    vector<Ciphertext> ct_deserialized_vec;

    if(!with_mac){
        for (int k = 0; k < input_size; k++) {
            Ciphertext deserialized_ct;
            high_resolution_clock::time_point start_deserialize = utility::timer_start();
            utility::deserialize_fhe((const char*)buf+idx, ct_size_vec[k], deserialized_ct,  seal->context_ptr);
            deserialize_time += utility::timer_end(start_deserialize);

            ct_deserialized_vec.push_back(deserialized_ct);
            idx += ct_size_vec[k];
        }
        performanceMetrics.deserialize = deserialize_time.count();
    }

    else{
       //verify
        idx = 0; idx2=0;
        string cur_plain, cur_mac;
        for (int k = 0; k < input_size; k++) {
            if(k<(input_size/2)){
                string tmp_str(buf+idx, ct_size_vec[k]-KEY_SIZE_BYTES); //FHE ct is saved together with MAC, so removing tag size
                cur_plain = tmp_str;
                idx += ct_size_vec[k];
                string str(buf+idx-KEY_SIZE_BYTES, KEY_SIZE_BYTES); //MAC tag is saved at the end of the FHE ct
                cur_mac = str;
            }
            else{
                string tmp_str(buf2+idx2, ct_size_vec[k]-KEY_SIZE_BYTES); //FHE ct is saved together with MAC, so removing tag size
                cur_plain = tmp_str;
                idx2 += ct_size_vec[k];
                string str(buf2+idx2-KEY_SIZE_BYTES, KEY_SIZE_BYTES); //MAC tag is saved at the end of the FHE ct
                cur_mac = str;
            }

            //cout<<"in verify, fhe_ctxt_number: "<<k<<endl;

            HMAC< SHA256 > hmac(key, KEY_SIZE_BYTES);
            const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;

            high_resolution_clock::time_point start_verify = utility::timer_start();
            StringSource(cur_plain + cur_mac, true,
                new HashVerificationFilter(hmac, NULL, flags)
            ); // StringSource
            verify_time += utility::timer_end(start_verify);
        }
        //cout << "verified data "  << endl;
        performanceMetrics.verify = verify_time.count();
        idx = 0; idx2=0;

        for (int k = 0; k < input_size/2; k++) {
            Ciphertext deserialized_ct;
            high_resolution_clock::time_point start_deserialize = utility::timer_start();
            utility::deserialize_fhe((const char*)buf+idx, ct_size_vec[k]-KEY_SIZE_BYTES, deserialized_ct,  seal->context_ptr);
            deserialize_time += utility::timer_end(start_deserialize);
            idx += ct_size_vec[k];
            ct_deserialized_vec.push_back(deserialized_ct);

            }
        for (int k = input_size/2; k < input_size; k++) {
            Ciphertext deserialized_ct;
            high_resolution_clock::time_point start_deserialize = utility::timer_start();
            //cout<<"in second option k>=(input_size/2)" <<endl;
            utility::deserialize_fhe((const char*)buf2+idx2, ct_size_vec[k]-KEY_SIZE_BYTES, deserialized_ct,  seal->context_ptr);
            deserialize_time += utility::timer_end(start_deserialize);
            idx2 += ct_size_vec[k];
            ct_deserialized_vec.push_back(deserialized_ct);
            }

        }
        performanceMetrics.deserialize = deserialize_time.count();
        //cout << "6 - deserialized data "  << endl;

        vector<double> output_vec;
        //decoding decrypting for tests
        for (int k = 0; k < input_size; k++) {
            vector<double> cur_res;
            Plaintext pt;
            seal->decryptor_ptr->decrypt(ct_deserialized_vec[k], pt);
            seal->encoder_ptr->decode(pt, cur_res);
            output_vec.push_back(cur_res[0]);
        }

        int counter=0;
        for( int h=0; h<input_size; h++){
                if( abs(input_vec[h] - output_vec[h] )>0.01){
                    counter++;
                    if(counter>10){
                        exit(1);
                    }
                    cout<< "error decrypting at index "<<h<<endl;
                    cout << "output_vec[h] " << output_vec[h] << endl;
                    cout << "input_vec[h] " <<input_vec[h] << endl;
                }
            }



        delete buf;
        delete buf2;
        Aws::ShutdownAPI(options);
    //cout << "after delete " <<  endl;

}

//baseline fhe storage and timing
void Test_Protocol::test_storage_fhe(ullong input_size, shared_ptr<seal_struct> seal, TP_performance_metrics& performanceMetrics){

    //encrypt and store fhe block to bucket:
    vector <vector<double>> main_vec;

    int max_ct_entries = _enc_init_params.polyDegree/2;
    //if input size=2 then run test only for this
    if(input_size<max_ct_entries){
        max_ct_entries= input_size;
    }

    std::string str1;
    int fhe_ctxt_number = ceil((input_size + 0.0) / max_ct_entries);
    //cout << "fhe_ctxt_number: " << fhe_ctxt_number <<" poly degree: "<<_enc_init_params.polyDegree<<endl;
    //cout << "MAX_CT_ENTRIES: " << max_ct_entries <<endl;
    //cout << "inputSize: " << input_size <<endl;

    vector<long> ct_size_vec;

    for (int k = 0; k < fhe_ctxt_number; k++) {
        vector<double> input_vec;
        for (int j = 0; j < max_ct_entries; j++) {
            input_vec.push_back(utility::x_gen(0.0, 1.0)); //generating random input data
        }
        main_vec.push_back(input_vec);
    }

    //encode and encrypt
    vector <Ciphertext> x_FHE;
    vector <Plaintext> x_pt;

    high_resolution_clock::time_point start_encode = utility::timer_start();
    for (int k = 0; k < fhe_ctxt_number; k++){
        Plaintext plain_x;
        seal->encoder_ptr->encode(main_vec[k], _enc_init_params.scale, plain_x);
        x_pt.push_back(plain_x);
    }
    nanoseconds encode_time = utility::timer_end(start_encode);
    performanceMetrics.encode_no_mac = encode_time.count();

    high_resolution_clock::time_point start_encrypt = utility::timer_start();
    for (int k = 0; k < fhe_ctxt_number; k++){
        Ciphertext x_FHE_tmp;
        seal->encryptor_ptr->encrypt(x_pt[k], x_FHE_tmp);
        x_FHE.push_back(x_FHE_tmp);
    }
    nanoseconds encrypt_time = utility::timer_end(start_encrypt);
    performanceMetrics.encrypt_no_mac = encrypt_time.count();


    //std::cout << "2 - encoded, encrypted" << endl;

    high_resolution_clock::time_point start_serialize = utility::timer_start();
    for (int k = 0; k < fhe_ctxt_number; k++){
        str1.append(utility::serialize_fhe(x_FHE[k]));
    }
    nanoseconds serialize_time = utility::timer_end(start_serialize);
    performanceMetrics.serialize_no_mac = serialize_time.count();

    //getting exact size for each ct
    for (int k = 0; k < fhe_ctxt_number; k++){
        ct_size_vec.push_back(utility::serialize_fhe(x_FHE[k]).size());
    }

    //std::cout << "3 - serialized" << endl;

    SDKOptions options;
    Aws::InitAPI(options);
    {
        S3Utility s3_utility(awsparams::region);

        high_resolution_clock::time_point start_store = utility::timer_start();
        s3_utility.save_to_bucket("fhe_inputs", awsparams::bucket_name, str1);
        nanoseconds store_time = utility::timer_end(start_store);
        performanceMetrics.store_no_mac = store_time.count();

        //std::cout << "4 - saved to bucket" << endl;
    }


    long ct_size = str1.size();
    cout <<"ct_size no hmac is: "<<ct_size<<endl;
    //allocating buffer for FHE load
    char* buf = new char[ct_size];
    if (buf == NULL){
        std::cerr << "Error: Cannot allocate buffer" << endl;
        return;
    }

    S3Utility s3utility(awsparams::region);

    //setting timer and loading FHE block
    high_resolution_clock::time_point start_load = utility::timer_start();
    s3utility.load_from_bucket("fhe_inputs", awsparams::bucket_name,  ct_size, buf);
    //cout << "Input buf is "  << buf << endl;
    nanoseconds load_time = utility::timer_end(start_load);
    performanceMetrics.load_no_mac = load_time.count();

   // cout << "Time to load data " << load_time.count() << endl;


    int idx = 0;
    vector<Ciphertext> ct_deserialized_vec;
    vector<vector<double>> output_vec;

    high_resolution_clock::time_point start_deserialize = utility::timer_start();
    for (int k = 0; k < fhe_ctxt_number; k++) {
        Ciphertext deserialized_ct;
        utility::deserialize_fhe((const char*)buf+idx, ct_size_vec[k], deserialized_ct,  seal->context_ptr);
        ct_deserialized_vec.push_back(deserialized_ct);
        idx += ct_size_vec[k];
    }
    nanoseconds deserialize_time = utility::timer_end(start_deserialize);
    performanceMetrics.deserialize_no_mac = deserialize_time.count();

    //decoding decrypting for tests
    for (int k = 0; k < fhe_ctxt_number; k++) {
        vector<double> tmp_vec;
        Plaintext pt;

        high_resolution_clock::time_point start_decrypt = utility::timer_start();
        seal->decryptor_ptr->decrypt(ct_deserialized_vec[k], pt);
        nanoseconds decrypt_time = utility::timer_end(start_decrypt);
        performanceMetrics.decrypt_no_mac = decrypt_time.count();

        high_resolution_clock::time_point start_decode = utility::timer_start();
        seal->encoder_ptr->decode(pt, tmp_vec);
        nanoseconds decode_time = utility::timer_end(start_decode);
        performanceMetrics.decode_no_mac = decode_time.count();
        output_vec.push_back(tmp_vec);
    }

    int counter=0;
    for( int h=0; h<fhe_ctxt_number; h++){
        for (int j = 0; j <max_ct_entries ; j++) {
            if( abs(main_vec[h][j] - output_vec[h][j] )>0.01){
                counter++;
                if(counter>10){
                    exit(1);
                }
                cout<< "error decrypting at index "<<j <<endl;
                cout << "output_vec[h][j] " << output_vec[h][j] << endl;
                cout << "main_vec[h][j] " <<main_vec[h][j] << endl;

            }
        }
    }

    //cout << "6 - deserialized data "  << endl;

    delete buf;
    Aws::ShutdownAPI(options);
//cout << "after delete " <<  endl;

}

void Test_Protocol::hmac_on_FHE(ullong input_size, shared_ptr<seal_struct> seal, TP_performance_metrics& performanceMetrics){

    //zero out all timers which are being added to in each run
    performanceMetrics.serialize = 0;
    performanceMetrics.hmac = 0;
    performanceMetrics.verify = 0;

    CryptoPP::AutoSeededRandomPool prng;
    byte key[KEY_SIZE_BYTES];
    prng.GenerateBlock(key, KEY_SIZE_BYTES);

   vector <vector<double>> main_vec;

    int max_ct_entries = _enc_init_params.polyDegree/2;
    if(input_size<max_ct_entries){
        max_ct_entries= input_size;
    }

    std::string str1;
    int fhe_ctxt_number = ceil((input_size + 0.0) / max_ct_entries);
    //cout << "fhe_ctxt_number: " << fhe_ctxt_number <<endl;
    //cout << "MAX_CT_ENTRIES: " << MAX_CT_ENTRIES <<endl;
    //cout << "inputSize: " << inputSize <<endl;

    vector<long> ct_size_vec;

    for (int k = 0; k < fhe_ctxt_number; k++) {
        vector<double> input_vec= utility::x_gen_int(0, _enc_init_params.prime_minus_1, max_ct_entries);
        //input_vec.push_back(40857238230);
        //input_vec.push_back(63042319820);
        //
        /*vector<double> input_vec;
        for (int j = 0; j < max_ct_entries; j++) {
            input_vec.push_back(utility::x_gen(0.0, 1.0)); //generating random input data
        }
        */
        main_vec.push_back(input_vec);
    }

    //encode and encrypt
    vector <Ciphertext> x_FHE;
    vector <Plaintext> x_pt;

    high_resolution_clock::time_point start_encode = utility::timer_start();
    for (int k = 0; k < fhe_ctxt_number; k++){
        Plaintext plain_x;
        seal->encoder_ptr->encode(main_vec[k], _enc_init_params.scale, plain_x);
        x_pt.push_back(plain_x);
    }
    nanoseconds encode_time = utility::timer_end(start_encode);
    performanceMetrics.encode = encode_time.count();

    high_resolution_clock::time_point start_encrypt = utility::timer_start();
    for (int k = 0; k < fhe_ctxt_number; k++){
        Ciphertext x_FHE_tmp;
        seal->encryptor_ptr->encrypt(x_pt[k], x_FHE_tmp);
        x_FHE.push_back(x_FHE_tmp);
    }
    nanoseconds encrypt_time = utility::timer_end(start_encrypt);
    performanceMetrics.encrypt = encrypt_time.count();

    //std::cout << "2 - encoded, encrypted" << endl;
    string tmp_str;

    for (int k = 0; k < fhe_ctxt_number; k++){
        //str1.append(utility::serialize_fhe(x_FHE[k]));
        high_resolution_clock::time_point start_serialize = utility::timer_start();
        std::string cur_string = utility::serialize_fhe(x_FHE[k]);
        nanoseconds serialize_time = utility::timer_end(start_serialize);
        performanceMetrics.serialize += serialize_time.count();

        string cur_mac; //setting empty string for mac

        try
        {
            HMAC< SHA256 > hmac(key, KEY_SIZE_BYTES);//init hmac
            high_resolution_clock::time_point hmac_time = utility::timer_start();

            //apply hmac
            StringSource ss2(cur_string, true,
                new HashFilter(hmac,
                    new StringSink(cur_mac)
                ) // HashFilter
            ); // StringSource
            auto durtion_hmac_time = utility::timer_end(hmac_time);
            performanceMetrics.hmac += durtion_hmac_time.count();

            if( cur_mac.size()!= KEY_SIZE_BYTES) { //HMAC with SHA256 is always 256 bits, 32 bytes.
                cout << " mac failed, mac tag size: " <<cur_mac.size() << endl;
            }
        }
        catch(const CryptoPP::Exception& e)
        {
            std::cerr << e.what() << endl;
            exit(1);
        }

        high_resolution_clock::time_point finish_serialize = utility::timer_start();
        str1.append(cur_string);
        str1.append(cur_mac);
        nanoseconds finish_serialize_time = utility::timer_end(finish_serialize);
        performanceMetrics.serialize += finish_serialize_time.count();
        //cout<<"finish_serialize_time.count(): " <<finish_serialize_time.count() <<endl;

    }

    //getting exact size for each ct
    for (int k = 0; k < fhe_ctxt_number; k++){
        ct_size_vec.push_back(utility::serialize_fhe(x_FHE[k]).size()+KEY_SIZE_BYTES);
    }

    //std::cout << "3 - serialized" << endl;

    SDKOptions options;
    Aws::InitAPI(options);
    {
        S3Utility s3_utility(awsparams::region);

        high_resolution_clock::time_point start_store = utility::timer_start();
        s3_utility.save_to_bucket("fhe_inputs", awsparams::bucket_name, str1);
        nanoseconds store_time = utility::timer_end(start_store);
        performanceMetrics.store = store_time.count();
        //std::cout << "4 - saved to bucket" << endl;
    }

    long ct_size = str1.size();
    cout <<"ct size w hmac is: "<<ct_size<<endl;
    //allocating buffer for FHE load
    char* buf = new char[ct_size];
    if (buf == NULL){
        std::cerr << "Error: Cannot allocate buffer" << endl;
        return;
    }

    S3Utility s3utility(awsparams::region);

    //setting timer and loading FHE block
    high_resolution_clock::time_point start_load = utility::timer_start();
    s3utility.load_from_bucket("fhe_inputs", awsparams::bucket_name,  ct_size, buf);
    //cout << "Input buf is "  << buf << endl;
    nanoseconds load_time = utility::timer_end(start_load);
    performanceMetrics.load = load_time.count();

   // cout << "Time to load data " << load_time.count() << endl;


   //verify
   int idx = 0;
    for (int k = 0; k < fhe_ctxt_number; k++) {
        string cur_plain(buf+idx, ct_size_vec[k]-KEY_SIZE_BYTES); //FHE ct is saved together with MAC, so removing tag size
        idx += ct_size_vec[k];
        string cur_mac(buf+idx-KEY_SIZE_BYTES, KEY_SIZE_BYTES); //MAC tag is saved at the end of the FHE ct

        //cout<<"fhe_ctxt_number: "<<k<<endl;

        HMAC< SHA256 > hmac(key, KEY_SIZE_BYTES);
        const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;

        high_resolution_clock::time_point verify_time = utility::timer_start();
        StringSource(cur_plain + cur_mac, true,
            new HashVerificationFilter(hmac, NULL, flags)
        ); // StringSource

        auto durtion_verify_time = utility::timer_end(verify_time);
        performanceMetrics.verify += durtion_verify_time.count();
   }

    idx = 0;
    vector<Ciphertext> ct_deserialized_vec;
    vector<vector<double>> output_vec;

    high_resolution_clock::time_point start_deserialize = utility::timer_start();
    for (int k = 0; k < fhe_ctxt_number; k++) {
        Ciphertext deserialized_ct;
        utility::deserialize_fhe((const char*)buf+idx, ct_size_vec[k]-KEY_SIZE_BYTES, deserialized_ct,  seal->context_ptr);
        ct_deserialized_vec.push_back(deserialized_ct);
        idx += ct_size_vec[k];
    }
    nanoseconds duration_deserialize_time = utility::timer_end(start_deserialize);
    performanceMetrics.deserialize = duration_deserialize_time.count();

    //decoding decrypting for tests
    for (int k = 0; k < fhe_ctxt_number; k++) {
        vector<double> tmp_vec;
        Plaintext pt;
        seal->decryptor_ptr->decrypt(ct_deserialized_vec[k], pt);
        seal->encoder_ptr->decode(pt, tmp_vec);
        output_vec.push_back(tmp_vec);
    }

    int counter=0;
    for( int h=0; h<fhe_ctxt_number; h++){
        for (int j = 0; j <max_ct_entries ; j++) {
            if( abs(main_vec[h][j] - output_vec[h][j] )>0.01){
                counter++;
                if(counter>10){
                    exit(1);
                }
                cout<< "error decrypting at index "<<j <<endl;
                cout << "output_vec[h][j] " << output_vec[h][j] << endl;
                cout << "main_vec[h][j] " <<main_vec[h][j] << endl;
            }
        }
    }
    delete buf;
    Aws::ShutdownAPI(options);
}

//test function for shifting pt and ct range to be in [-1,1] for input size up to poly degree/2
void Test_Protocol::shift_data_range(ullong input_size)
{
    Servers_Protocol srv_protocol;
     vector<double> input_vec = utility::x_gen_int(0, _enc_init_params.prime_minus_1, input_size);

     vector<double> input_vec_frac;
    for(int i=0; i<input_size; i++){
        input_vec_frac.push_back((input_vec[i]/(_enc_init_params.prime_minus_1/2))-1);

        //cout<<input_vec_frac[i]<<endl;
        if(input_vec_frac[i]>1 || input_vec_frac[i]<-1){
            cout <<"cleartext not in range: " <<input_vec_frac[i]<<endl;
        }
    }

    //for ctxt:
    Plaintext  input_pt, div_vec_pt, minus_1_vec_pt, out_pt;
    Ciphertext input_ct, out_ct;
    std::shared_ptr<seal_struct> seal = srv_protocol.gen_seal_params(_enc_init_params.polyDegree, _enc_init_params.bit_sizes, _enc_init_params.scale);

    seal->encoder_ptr->encode(input_vec, _enc_init_params.scale, input_pt);
    seal->encryptor_ptr->encrypt(input_pt, input_ct);

    vector<double> vec_div(input_size, 1.0/(_enc_init_params.prime_minus_1/2.0));
    vector<double> vec_minus_1(input_size, (-1));


    seal->encoder_ptr->encode(vec_div, input_ct.parms_id(),_enc_init_params.scale, div_vec_pt);
    seal->evaluator_ptr->multiply_plain_inplace(input_ct, div_vec_pt);

     seal->evaluator_ptr->rescale_to_next_inplace(input_ct);
    input_ct.scale() = _enc_init_params.scale;

    seal->encoder_ptr->encode(vec_minus_1, input_ct.parms_id(), _enc_init_params.scale, minus_1_vec_pt);
    seal->evaluator_ptr->add_plain_inplace(input_ct, minus_1_vec_pt);

    vector<double> output_vec;
    seal->decryptor_ptr->decrypt(input_ct, out_pt);
    seal->encoder_ptr->decode(out_pt, output_vec);

    for(int i=0; i<input_size; i++){
        //cout<<output_vec[i]<<endl;
        if(output_vec[i]>1 || output_vec[i]<-1){
          cout <<"in ct not in range: " <<output_vec[i]<<endl;
        }
    }

}

void Test_Protocol::test_storage_cleartext(ullong input_size){
    //generating vec, 3 doubles for each input item
    ullong vec_size = input_size*3;
    cout <<"vec size is: "<<vec_size<<endl;
    vector<double> data_vec(input_size, vec_size);
    //vector<double> data_vec = utility::x_gen_int(0, _enc_init_params.prime_minus_1, vec_size);
    //vector<double> data_vec = {1,2,3};

    //writing vec to stream
    std::ostringstream os;
    for (ullong i = 0; i < vec_size; i++){
        os.write(reinterpret_cast<const char*>(&data_vec[i]), sizeof(double));
    }

    //saving to bucket
    SDKOptions options;
    Aws::InitAPI(options);
    {
        S3Utility s3Utility(awsparams::region);
        s3Utility.save_to_bucket("cleartext_inputs", awsparams::bucket_name, os.str());

    }
    Aws::ShutdownAPI(options);
}



int Test_Protocol::test_compact_HE_mac_optimized(ullong input_size){

    vector<vector<double>> x_int_vec, x_frac_vec;
    int N_agg = ceil((input_size+0.0)/_enc_init_params.max_ct_entries);

    MAC mac(_enc_init_params);

    vector<K_MAC_Batched> kmac_vec;
    int len_vec = std::min(int(input_size), _enc_init_params.max_ct_entries);
    int last_vec_size = (input_size%_enc_init_params.max_ct_entries == 0) ? len_vec : input_size % _enc_init_params.max_ct_entries;
    //cout <<"N_agg: "<<N_agg << " len_vec: "<<len_vec<<endl;

    //generating random input vectors (outputs of secret sharing) and key mac
    for(int j=0; j<N_agg; j++)
    {
        int len = len_vec;
        if(j==(N_agg-1))
        {
            len = last_vec_size;
        }
        vector<double> x_int = utility::x_gen_int(0, 1, len);
        vector<double> x_frac = utility::x_gen_int(0, _enc_init_params.prime_minus_1, len);

        x_int_vec.push_back(x_int);
        x_frac_vec.push_back(x_frac);

        K_MAC_Batched kmac(_enc_init_params.prime);
        vector<double> a_int = utility::x_gen_int(0, 1, len_vec); //generating random bit vec
        vector<double> a_frac = utility::x_gen_int(0,  _enc_init_params.prime_minus_1, len_vec);
        kmac.a_int = a_int;
        kmac.a_frac = a_frac;

        if(j==0){ //other values than a int, a frac are only necessary for number of slot count
            kmac.b = utility::x_gen_int(0, _enc_init_params.prime_minus_1, len_vec);//utility::x_gen_int(0, _enc_init_params.prime_minus_1, 1)[0];
            kmac.c_alpha = utility::x_gen_int(0, _enc_init_params.prime_minus_1, len_vec);
            kmac.c_beta = utility::x_gen_int(0, _enc_init_params.prime_minus_1, len_vec);
            kmac.d_alpha=utility::x_gen_int(0, 1, len_vec); //generating random bit vec
            kmac.d_beta=utility::x_gen_int(0, 1, len_vec); //generating random bit vec
        }

        kmac_vec.push_back(kmac);
    }

    cout << "x_int[0]: " << x_int_vec[0][0] << " x_frac[0]: " << x_frac_vec[0][0] << endl;
    cout << "a_int[0]: " <<kmac_vec[0].a_int[0] << " a_frac[0]: " <<kmac_vec[0].a_frac[0] <<" kmac.b: "<<kmac_vec[0].b[0]<<" kmac.c_alpha: "<<kmac_vec[0].c_alpha[0] << " kmac.c_beta: " <<kmac_vec[0].c_beta[0] <<endl;
    cout << "d_alpha[0]: " << kmac_vec[0].d_alpha[0] << " d_beta[0]: " << kmac_vec[0].d_beta[0] << endl;

    //starting MAC computation
    double prime_square = pow(_enc_init_params.prime, 2);
    mac_tag_batched_optimized optimized_mac;
	int num_of_secret_shares = input_size;
	vector<double> result_vec(len_vec, 0.0); //always has to be longest vector //changed from slot count - TODO: change origin.

    for(int j=0; j<N_agg; j++){
        // calculate x_int * a_int + x_frac * a_frac and then add to the result vector

        int len = len_vec;
        if(j==(N_agg-1))
        {
            len = last_vec_size;
        }
        vector<double> x_int_for_mac(len, 0.0);
        vector<double>  x_frac_for_mac(len, 0.0);

        std::transform(x_int_vec[j].begin(), x_int_vec[j].end(), kmac_vec[j].a_int.begin(), x_int_for_mac.begin(), std::multiplies<double>());
        std::transform(x_frac_vec[j].begin(), x_frac_vec[j].end(), kmac_vec[j].a_frac.begin(), x_frac_for_mac.begin(), std::multiplies<double>());
        std::transform(x_int_for_mac.begin(), x_int_for_mac.end(), x_frac_for_mac.begin(), x_int_for_mac.begin(), std::plus<double>());
        std::transform(result_vec.begin(), result_vec.end(), x_int_for_mac.begin(), result_vec.begin(), std::plus<double>());

    }

    // add b to the sum of (x_int * a_int + x_frac * a_frac)
    std::transform(result_vec.begin(), result_vec.end(), kmac_vec[0].b.begin(), result_vec.begin(), std::plus<double>());
    optimized_mac = mac.compact_mac_batched_optimized(kmac_vec[0], result_vec);

    vector<double> alpha_int_vec, beta_int_vec;
    //mac tag part two - seperate to y_beta_int, y_alpha_int and encrypt
    for(int i=0; i<optimized_mac.mac_part2.size(); i++){

        unsigned char val = optimized_mac.mac_part2[i];
        double pSquare = pow(_enc_init_params.prime, 2);
        double pTriple = pow(_enc_init_params.prime, 3);

        double alpha_int = (((int)val >> 1) & 0x1) * pTriple;
        double beta_int = ((int)val & 0x1) * pSquare;

        /*
        cout.precision(15);
        cout <<"for i: " <<i <<" alpha_int: " <<alpha_int << " beta_int: "<<beta_int<<endl;
        cout <<"optimized_mac.mac_part1[i]: " <<optimized_mac.mac_part1[i]<<endl; */

        alpha_int_vec.push_back(alpha_int);
        beta_int_vec.push_back(beta_int);
    }

    //aux encryptions
    shared_ptr<seal_struct> seal_struct = set_seal_struct();
    Plaintext pt_t_r, pt_alpha_int, pt_beta_int;
    Ciphertext ct_t_r, ct_alpha_int, ct_beta_int;

    seal_struct->encoder_ptr->encode(optimized_mac.mac_part1, _enc_init_params.scale, pt_t_r);
    seal_struct->encryptor_ptr->encrypt(pt_t_r, ct_t_r);

    seal_struct->encoder_ptr->encode(alpha_int_vec, _enc_init_params.scale, pt_alpha_int);
    seal_struct->encryptor_ptr->encrypt(pt_alpha_int, ct_alpha_int);
    seal_struct->encoder_ptr->encode(beta_int_vec, _enc_init_params.scale, pt_beta_int);
    seal_struct->encryptor_ptr->encrypt(pt_beta_int, ct_beta_int);

    Ciphertext batched_y_ct;
    for(int j=0; j<N_agg; j++){
        Plaintext pt_x_int_const, pt_x_frac_const;
        Ciphertext ct_x_int_const, ct_x_frac_const;

        seal_struct->encoder_ptr->encode(x_int_vec[j], _enc_init_params.scale, pt_x_int_const);
        seal_struct->encryptor_ptr->encrypt(pt_x_int_const, ct_x_int_const);

        seal_struct->encoder_ptr->encode(x_frac_vec[j], _enc_init_params.scale, pt_x_frac_const);
        seal_struct->encryptor_ptr->encrypt(pt_x_frac_const, ct_x_frac_const);

        //verify by DS
        if(j==0){
            batched_y_ct = verifyHE_batched_y(seal_struct, kmac_vec[j], ct_x_int_const, ct_x_frac_const);
        }
        else{ // this is adds a_int*x_int + a_frac*x_frac values calculated earlier to all the same values from the previous ciphertexts
            Ciphertext batched_y_ct_temp = verifyHE_batched_y(seal_struct, kmac_vec[j], ct_x_int_const, ct_x_frac_const);
            seal_struct->evaluator_ptr->mod_switch_to_inplace(batched_y_ct, batched_y_ct_temp.parms_id());
            seal_struct->evaluator_ptr->add_inplace(batched_y_ct, batched_y_ct_temp);
        }

    }
    Ciphertext batched_y_tag_ct = verifyHE_batched_y_tag(seal_struct, len_vec, kmac_vec[0], ct_t_r, ct_alpha_int, ct_beta_int);

    Ciphertext diff_ct;
    vector<Ciphertext>(diffCt_shared);
    seal_struct->evaluator_ptr->sub(batched_y_ct, batched_y_tag_ct, diff_ct);
    diffCt_shared.push_back(diff_ct);

    return tests::is_MAC_HE_valid(seal_struct,  make_shared<vector<Ciphertext>>(diffCt_shared), input_size, _enc_init_params.max_ct_entries, "MAC batched scheme", true);

}


Ciphertext Test_Protocol::verifyHE_batched_y(const shared_ptr<seal_struct> seal_struct , K_MAC_Batched kmac, Ciphertext ct_x_int, Ciphertext ct_x_frac){

    MAC mac(_enc_init_params);
    Ciphertext ct_result;
    Plaintext pt_a_int, pt_a_frac;

	seal_struct->encoder_ptr->encode(kmac.a_int, _enc_init_params.scale, pt_a_int);
	seal_struct->encoder_ptr->encode(kmac.a_frac, _enc_init_params.scale, pt_a_frac);

	mac.mult_ct_pt_inplace(seal_struct, ct_x_int, pt_a_int);
	mac.mult_ct_pt_inplace(seal_struct, ct_x_frac, pt_a_frac);

	seal_struct->evaluator_ptr->add(ct_x_int, ct_x_frac, ct_result);

    return ct_result;
}


Ciphertext Test_Protocol::verifyHE_batched_y_tag(const shared_ptr<seal_struct> seal_struct , int len_vec, K_MAC_Batched kmac, Ciphertext ct_tr, Ciphertext ct_alpha_int, Ciphertext ct_beta_int){

    MAC mac(_enc_init_params);
    double p_square = _enc_init_params.prime * _enc_init_params.prime;
	double p_triple = p_square * _enc_init_params.prime;
	vector<double> signPTriple(len_vec, 1); //if d=0 then: (-1)^d *p^3 = p^2
	vector<double> signPSquare(len_vec, 1); //if d=0 then: (-1)^d *p^2 = p^3
	vector<double> cleartext_calc(len_vec, 0); //vector to sum all cleartext operations in verify

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

	mac.mult_ct_pt_inplace(seal_struct, ct_alpha_int, pt_signPTriple); //(-1)^d_alpha*p^3* y_alpha_int
	mac.mult_ct_pt_inplace(seal_struct, ct_beta_int, pt_signPSquare); //(-1)^d_beta*p^2* y_beta_int
    seal_struct->evaluator_ptr->add(ct_alpha_int, ct_beta_int, y_comp); //(-1)^d_alpha*p^3* y_alpha_int + (-1)^d_beta*p^2* y_beta_int

	seal_struct->evaluator_ptr->mod_switch_to_inplace(ct_tr, y_comp.parms_id());
	seal_struct->evaluator_ptr->add_inplace(y_comp, ct_tr); //(-1)^d_alpha*p^3* y_alpha_int + (-1)^d_beta*p^2* y_beta_int+y_t

    seal_struct->encoder_ptr->encode(cleartext_calc, y_comp.parms_id(), _enc_init_params.scale, cleartext_calc_pt);
	seal_struct->evaluator_ptr->add_plain_inplace(y_comp, cleartext_calc_pt);


	return y_comp;
}



int Test_Protocol::test_compact_unbatched_HE_mac(ullong input_size){

    MAC mac(_enc_init_params);

    K_MAC kmac(_enc_init_params.prime);
    vector<double> x_int, x_frac;
    int len_vec = int(input_size); //running up to 1 ctxt

    //generating random kmac
    kmac.a_int = utility::x_gen_int(0, _enc_init_params.prime_minus_1, len_vec);
    kmac.a_frac = utility::x_gen_int(0, _enc_init_params.prime_minus_1, len_vec);
    kmac.b = utility::x_gen_int(0, _enc_init_params.prime_minus_1, len_vec);
    kmac.c_alpha = utility::x_gen_int(0, _enc_init_params.prime_minus_1, len_vec);
    kmac.d_alpha = utility::x_gen_int(0, 1, len_vec);

    //generating random input vectors (outputs of secret sharing)
    x_int = utility::x_gen_int(0, 1, len_vec);
    x_frac = utility::x_gen_int(0, _enc_init_params.prime_minus_1, len_vec);
    //x_frac = utility::x_gen_int(0, 300, len_vec);


    //cout <<"in test_compact_HE_mac: a_frac[0]: " <<kmac.a_frac[0] <<" kmac.b: "<<kmac.b <<" kmac.c: "<<kmac.c[0] <<"kmac.d[0]: "<<kmac.d[0] <<endl;

    cout<<"x_int_vec.size(): "<<x_int.size() <<endl;
    cout <<"x_int[0]: " <<x_int[0]<<endl;


    compact_unbatched_mac_tag tag = mac.compact_unbatched_mac(kmac, x_int, x_frac, input_size); //for input vector of x_int, x_frac we ouput 1 tag only

	shared_ptr<seal_struct> seal_struct = set_seal_struct();

    //encode encrypt to HE ctxt
    Plaintext x_int_pt, x_frac_pt;
    Ciphertext x_int_ct, x_frac_ct;
    seal_struct->encoder_ptr->encode(x_int, _enc_init_params.scale, x_int_pt);
    seal_struct->encryptor_ptr->encrypt(x_int_pt, x_int_ct);

    seal_struct->encoder_ptr->encode(x_frac, _enc_init_params.scale, x_frac_pt);
    seal_struct->encryptor_ptr->encrypt(x_frac_pt, x_frac_ct);

    double p = _enc_init_params.prime;
    for(int i=0;i<len_vec; i++){
        tag.y_alpha_frac->at(i) *=p;
        tag.y_alpha_frac->at(i)+= tag.y_r->at(i);
    }

    Ciphertext y_r_ct, y_alpha_int_ct, y_alpha_frac_ct, y_t_ct;
    Plaintext y_r_pt, y_alpha_int_pt, y_alpha_frac_pt, y_t_pt;


    seal_struct->encoder_ptr->encode(*tag.y_alpha_int, _enc_init_params.scale, y_alpha_int_pt);
    seal_struct->encryptor_ptr->encrypt(y_alpha_int_pt, y_alpha_int_ct);

    seal_struct->encoder_ptr->encode(*tag.y_alpha_frac, _enc_init_params.scale, y_t_pt);
    seal_struct->encryptor_ptr->encrypt(y_t_pt, y_t_ct);

    seal_struct->encoder_ptr->encode(*tag.y_r, _enc_init_params.scale, y_r_pt);
    seal_struct->encryptor_ptr->encrypt(y_r_pt, y_r_ct);


    //inserting ctxt to mac tag he struct
    mac_tag_ct tag_he;
    /*
    tag_he.y_r_ct = make_shared<Ciphertext>(y_r_ct);
    tag_he.y_alpha_int_ct = make_shared<Ciphertext>(y_alpha_int_ct);
    tag_he.y_alpha_frac_ct = make_shared<Ciphertext>(y_alpha_frac_ct);
    */
    tag_he.z_qmskd_ct = make_shared<Ciphertext>(y_alpha_int_ct);
    tag_he.t_r_ct =make_shared<Ciphertext>(y_t_ct);

    //computing verify and diff between mac tag and verify
	vector<Ciphertext> diffCt;
	bool squareDiff  =true;

	diffCt.push_back(compact_unbatched_VerifyHE(seal_struct , kmac, x_int_ct, x_frac_ct, tag_he, true,input_size));

	shared_ptr<vector<Ciphertext>> diffCt_shared = make_shared<vector<Ciphertext>>(diffCt);

	return tests::is_MAC_HE_valid(seal_struct,  diffCt_shared, input_size, _enc_init_params.max_ct_entries, "Compact MAC unbatched", true);
}

const Ciphertext& Test_Protocol::compact_unbatched_VerifyHE(const shared_ptr<seal_struct> seal_struct , K_MAC kmac, Ciphertext& x_int,
	Ciphertext& x_frac, mac_tag_ct& tag_he, bool squareDiff, int len)
{
    MAC mac(_enc_init_params);

	// this function computes the following:
	// In cleartext form: (-1)^d*(-d)*p^2-c*p-b
	// In ciphertext form: p^2*(-1)^d*z_qmskd+t_r -ax
	// It then adds the cleartext and the ciphertext values. When the value is close to 0, the mac is valid

	double p_square = _enc_init_params.prime * _enc_init_params.prime;
	vector<double> signPSquare(len, p_square); //if d=0 then: (-1)^d *p^2 = p^2
	vector<double> cleartext_calc(len, 0); //vector to sum all cleartext operations in verify

	//high_resolution_clock::time_point start_verify = utility::timer_start();
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

	mac.mult_ct_pt_inplace(seal_struct, *tag_he.z_qmskd_ct, pt_signPSquare); //(-1)^d *p^2 *z_qmskd

	Ciphertext y_comp;
	seal_struct->evaluator_ptr->mod_switch_to_inplace(*tag_he.t_r_ct, tag_he.z_qmskd_ct.get()->parms_id());
	seal_struct->evaluator_ptr->add(*tag_he.t_r_ct, *tag_he.z_qmskd_ct, y_comp); //(-d)*(-1)^d* p^2 * z_qmskd+ t_r


    seal_struct->encoder_ptr->encode(cleartext_calc, y_comp.parms_id(), _enc_init_params.scale, cleartext_calc_pt);
	seal_struct->evaluator_ptr->add_plain_inplace(y_comp, cleartext_calc_pt);

	Plaintext a_int_pt, a_frac_pt;
	seal_struct->encoder_ptr->encode(kmac.a_int, x_int.parms_id(), _enc_init_params.scale, a_int_pt);
	seal_struct->encoder_ptr->encode(kmac.a_frac, x_frac.parms_id(), _enc_init_params.scale, a_frac_pt);
	mac.mult_ct_pt_inplace(seal_struct, x_int, a_int_pt);
	mac.mult_ct_pt_inplace(seal_struct, x_frac, a_frac_pt);

	seal_struct->evaluator_ptr->add_inplace(x_int, x_frac);

	seal_struct->evaluator_ptr->sub(y_comp, x_int, x_int); //compute y-y' , output should be 0

    //performanceMetrics->verify += utility::timer_end(start_verify).count();
    //apply square diffs
	if (squareDiff)
    {
        high_resolution_clock::time_point start_square_diff = utility::timer_start();
		seal_struct->evaluator_ptr->square_inplace(x_int); //computing sqauare diff
		seal_struct->evaluator_ptr->relinearize_inplace(x_int, *seal_struct->relink_ptr); //must do after ctxt * ctxt multiplication
		seal_struct->evaluator_ptr->rescale_to_next_inplace(x_int); //see if necessary for decryption, possible
		x_int.scale() = _enc_init_params.scale;
		//performanceMetrics->square_diff += utility::timer_end(start_square_diff).count();
	}

	return x_int;

}

void Test_Protocol::test_hkdf(TP_performance_metrics& performanceMetrics){
	using namespace CryptoPP;
	// Define parameters
	byte ikm[32] =
	{0x00, 0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08, 0x09,
	0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
	0x0F, 0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
	std::string info = "Example HKDF Info";
	byte derivedKey[32]; // Length of derived key

	// Create the HKDF object
	HKDF<SHA256> hkdf;

	// Derive the key with an empty salt (equivalent to all-zero salt)
    high_resolution_clock::time_point time_hkdf= utility::timer_start();
	hkdf.DeriveKey(derivedKey, sizeof(derivedKey), ikm, sizeof(ikm), nullptr, 0, (const byte*)info.data(), info.size());
    performanceMetrics.hkdf = utility::timer_end(time_hkdf).count();

	// Print the derived key in hexadecimal format
	std::string encoded;
	HexEncoder encoder(new StringSink(encoded));
	encoder.Put(derivedKey, sizeof(derivedKey));
	encoder.MessageEnd();
	//std::cout << "Derived Key: " << encoded << std::endl;

}


void Test_Protocol::test_crypto_sink_hmac(TP_performance_metrics& performanceMetrics){

    const byte k[] = {
        0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        /*
      0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,
      0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,
      0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,
      0x1,0x1*/
    };

    string plain = "Example HMAC plain";
    string mac, encoded;

    // Pretty print key
    encoded.clear();
    CryptoPP::StringSource ss1(k, sizeof(k), true,
        new HexEncoder(new StringSink(encoded)) ); // HexEncoder StringSource

    //cout << "key: " << encoded << endl;
    //cout << "plain text: " << plain << endl;

    try
    {
        high_resolution_clock::time_point init_hmac = utility::timer_start();
        CryptoPP::HMAC< SHA256 > hmac(k, sizeof(k));
        nanoseconds hmac_time = utility::timer_end(init_hmac);

        high_resolution_clock::time_point update_hmac = utility::timer_start();
        StringSource ss2(plain, true,
            new HashFilter(hmac, new StringSink(mac) ) ); // HashFilter// StringSource
        performanceMetrics.hmac = utility::timer_end(update_hmac).count();

        //cout << "hmac len : "<<mac.size()<< " data: " << mac << endl;

    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << endl;
        exit(1);
    }
    mac.clear();

    // Pretty print
    encoded.clear();
    StringSource ss3(mac, true,
        new HexEncoder( new StringSink(encoded)) ); // HexEncoder // StringSource

    //cout << "hmac len : "<<encoded.size()<< " data: " << encoded << endl;
}


int Test_Protocol::test_openssl_hkdf(bool is_sha512, TP_performance_metrics& performanceMetrics){

    int num_rep = 747;
    performanceMetrics.hkdf = 0; //resetting for each separate run
    for(int i=0; i<num_rep; i++){

        // Input keying material (IKM)
        unsigned char ikm[] = {
            0x00, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x09,
            0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        };

        //unsigned char ikm[] = "input keying material";
        size_t ikm_len = sizeof(ikm) - 1;

        string temp_salt = std::to_string((int)(utility::x_gen_int(0,10000, 1)[0]));

        // Salt (optional, can be NULL)
        unsigned char* salt = new unsigned char[temp_salt.size()+1];
        std::memcpy(salt, temp_salt.c_str(),temp_salt.size()+1);
        size_t salt_len = sizeof(salt) - 1;

        // Info (optional, can be NULL)
        unsigned char info[] = "optional info";
        size_t info_len = sizeof(info) - 1;

        // SHA-256 hash length in bytes
        const size_t sha512_len = 64;


        // our necessary output length for HKDF-SHA
        size_t output_len;
        if(is_sha512){
            output_len = sha512_len * 255;
        }
        else{
            output_len = 32;
        }

        // Allocate space for the derived key
        std::vector<unsigned char> output_key(output_len);

        // Create HKDF context
        EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
        if (!kdf) {
            std::cerr << "Failed to fetch HKDF KDF" << std::endl;
            return 1;
        }

        EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
        if (!kctx) {
            std::cerr << "Failed to create HKDF context" << std::endl;
            EVP_KDF_free(kdf);
            return 1;
        }

        uint64_t mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;

        string sha;
        if(is_sha512){
            sha = "SHA512";
        }
        else{
            sha = "SHA256";
        }

        // Set up the parameters for HKDF
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char *>(sha.c_str()), 0),
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, ikm_len),
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_len),
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, info_len),
            OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_MODE, &mode),
            OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &output_len),
            OSSL_PARAM_construct_end()
        };


        // Perform the key derivation
        if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
            std::cerr << "Failed to set HKDF parameters" << std::endl;
            EVP_KDF_CTX_free(kctx);
            EVP_KDF_free(kdf);
            return 1;
        }

        high_resolution_clock::time_point derive_hkdf = utility::timer_start();
        if (EVP_KDF_derive(kctx, output_key.data(), output_len, params) <= 0) {
            std::cerr << "Failed to derive key" << std::endl;
            EVP_KDF_CTX_free(kctx);
            EVP_KDF_free(kdf);
            return 1;
        }
        performanceMetrics.hkdf += utility::timer_end(derive_hkdf).count();

    /*
        // Output the derived key (for demonstration purposes)
        //std::cout << "Derived key: ";
        for (unsigned char byte : output_key) {
            std::printf("%02x", byte);
        }
        std::cout << std::endl;
    */
        // Clean up
        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
        EVP_cleanup();
    }

    return 0;

}

