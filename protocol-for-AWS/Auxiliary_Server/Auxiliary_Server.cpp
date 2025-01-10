#include "Auxiliary_Server.h"
#include <aws/core/Aws.h>
#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curses.h>
#include <signal.h>

using namespace Aws;
using namespace seal;
using namespace utility;

#define PORT 8080

bool abortRequested = false;

// a type for holding a list of buffer pointer, buffer size, filename and number of encoded doubles tuples
// used for loading data from the bucket into the buffer
typedef vector<bucket_data> buffer_data_vec;


Auxiliary_Server::Auxiliary_Server(int data_points_num, bool read_keys_from_file, bool with_mac, bool batched, string enc_init_params_file, std::ofstream *metrics_file_in)
{
    _data_points_num = data_points_num;
    _with_mac = with_mac;
    _read_keys_from_file = read_keys_from_file;
    InitEncParams(&_enc_init_params, enc_init_params_file);
    _batched_size = (batched) ? ceil((double)data_points_num / _enc_init_params.max_ct_entries) : 0;
    // create metrics file
    metrics_file = metrics_file_in;
}


std::ostream& operator<<(std::ostream& out, const AS_performance_metrics& asPerformanceMetrics) {
    return out  << asPerformanceMetrics.load_stored_data/1000 << "," <<
               asPerformanceMetrics.encode_encrypt/1000 << "," <<  asPerformanceMetrics.serialize/1000 << ","
               << asPerformanceMetrics.send_data/1000 << "," << asPerformanceMetrics.sent_size_in_bytes << ","
               << asPerformanceMetrics.end2end/1000;
}

std::string AS_performance_metrics::getHeader(){
    return "load stored data,encode and encrypt,serialize,send data, sent bytes, end2end_as";
}


inline shared_ptr<vector<double>> Auxiliary_Server::FillVecByCTSize(std::vector<double>::iterator start, int ct_index){
    std::vector<double> v1(start + ct_index * _enc_init_params.max_ct_entries, start + (ct_index + 1) * _enc_init_params.max_ct_entries);
    return make_shared<vector<double>>(v1);
}

inline shared_ptr<vector<double>> Auxiliary_Server::FillVecByInputSize(std::vector<double>::iterator start, int ct_index){
    std::vector<double> v1(start + ct_index * _enc_init_params.max_ct_entries, start + _data_points_num);
    return make_shared<vector<double>>(v1);
}

inline string Auxiliary_Server::EncodeEncryptSerialize(vector<double> &vec, const shared_ptr<seal_struct> seal, AS_performance_metrics *performanceMetrics){
    Plaintext pt; Ciphertext ct;
    std::string serialized_str;

    high_resolution_clock::time_point start_encode_encrypt = utility::timer_start();

    seal->encoder_ptr->encode(vec, _enc_init_params.scale, pt);
    seal->encryptor_ptr->encrypt(pt, ct);

    performanceMetrics->encode_encrypt += utility::timer_end(start_encode_encrypt).count();

    high_resolution_clock::time_point start_serialize = utility::timer_start();

    serialized_str = utility::serialize_fhe(ct);

    performanceMetrics->serialize += utility::timer_end(start_serialize).count();


    return serialized_str;
}



void Auxiliary_Server::SetupServerSocket(int &server_socket)
{
    int opt = 1;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // create socket file descriptor
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("Socket creation failed");
        exit(1);
    }

    // attach socket to port
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        perror("Failed to set socket");
        exit(1);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("Bind failed");
        exit(1);
    }

    int flags = fcntl(server_socket, F_GETFL, 0);
    fcntl(server_socket, F_SETFL, flags | O_NONBLOCK);

    if (listen(server_socket, 3) < 0)
    {
        perror("Listen failed");
        exit(1);
    }

}

void Auxiliary_Server::AcceptConnections(int server_socket)
{
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    while (!abortRequested)
    {
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket < 0)
        {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
            {
                // no incoming connection, continue waiting
                continue;
            }

            std::cerr << "Accept Failed" << strerror(errno) << std::endl;
            continue;
        }

        cout << "Sending data" << endl;
        EncryptAndSendData(client_socket);
        cout << "Done sending data" << endl << endl;

        close(client_socket);
    }

}

void signalHandler(int signum)
{
    if (signum == SIGINT)
    {
        std::cout << "Abort requested by user." << std::endl;
        abortRequested = true;
    }
}


void Auxiliary_Server::StartServer(void)
{
    int server_socket;

    SetupServerSocket(server_socket);

    // ignore sigpipe errors as the code will handle socket write errors
    signal(SIGPIPE, SIG_IGN);

    // signal handler for Ctrl-C
    signal(SIGINT, signalHandler);

    std::cout << "Server listening on port " << PORT << std::endl << "Press Ctrl+C to abort" << std::endl;

    while (!abortRequested)
    {
        // check for keyboard input and user abort
        int ch = getch();
        if (ch !=  ERR)
        {
            // if Ctrl+C was pushed
            if(ch == 3)
            {
                std::cout << "Abort Requested" << std::endl;
                abortRequested = true;
                break;
            }
        }

        // check for incoming connection
        AcceptConnections(server_socket);

        // sleep for 100 milliseconds to prevent busy wait
        usleep(100000);
    }

    close(server_socket);

}

// extract the secret share values from the double read from the bucket
// s_q = double val / p
// s_r = double val % p
void Auxiliary_Server::parse_double_into_secret_share(double val, std::vector<std::vector<double>>& enc_vector_list, long index)
{
    double s_q, s_r;

    auto dv = lldiv(val, _enc_init_params.prime);
    s_q = dv.quot;
    s_r = dv.rem;

    enc_vector_list[index].push_back(s_q);
    enc_vector_list[index + 1].push_back(s_r);
}

// extract the mac values from the double read from the bucket
// z_q = double val / p^2
// temp = double val % p^2
// z_r = temp / p
// y_r = temp % p

void Auxiliary_Server::parse_double_into_mac(double val, std::vector<std::vector<double>>& enc_vector_list, long index)
{
    double z_q, z_r, y_r, temp;
    ullong prime_square = pow(_enc_init_params.prime, 2);

    auto dv = lldiv(val, prime_square);
    z_q = dv.quot;
    temp = dv.rem;
    dv = lldiv(temp, _enc_init_params.prime);
    z_r = dv.quot;
    y_r = dv.rem;

    enc_vector_list[index].push_back(z_r);
    enc_vector_list[index + 1].push_back(y_r);
    enc_vector_list[index + 2].push_back(z_q);
}

void Auxiliary_Server::parse_double_into_mac_batched_part1(double val, std::vector<std::vector<double>>& enc_vector_list, long index)
{
    // No need for parsing here, as the restore is done on the same value.
    enc_vector_list[index].push_back(val);
}

int the_counter = 0;
void Auxiliary_Server::parse_double_into_mac_batched_part2(double val, std::vector<std::vector<double>>& enc_vector_list, long index)
{
    double alpha_int, beta_int;
    double pSquare = pow(_enc_init_params.prime, 2);
    double pTriple = pow(_enc_init_params.prime, 3);


    alpha_int = (((int)val >> 1) & 0x1) * pTriple;
    beta_int = ((int)val & 0x1) * pSquare;

    enc_vector_list[index].push_back(alpha_int);
    enc_vector_list[index + 1].push_back(beta_int);
}


void Auxiliary_Server::EncryptAndSendData(int the_socket)
{
    SDKOptions options;
    Aws::InitAPI(options);
    {
        S3Utility s3Utility(awsparams::region);
        shared_ptr<seal_struct> seal_ptr;
        Servers_Protocol srvProtocol;
        AS_performance_metrics performanceMetrics;
        int remaining_data_points_num, num_of_ct, num_of_mac_ct;
        int i, j, k;
        int buffer_index = 0;
        int sent = 0;
        int sent_times = 0;
        // number of doubles used for secret share and mac
        int secret_share_encoded_doubles = 2;
        int mac_encoded_doubles = 3;
        char* buffer_tag_sr;
        char* buffer_tag_sq;

        size_t double_size = sizeof(double);

        high_resolution_clock::time_point end2end = utility::timer_start();

        EncryptionParameters parms;
        seal::PublicKey pk_fhe;
        string pk_object_name = string("pk-fhe-") + std::to_string(_enc_init_params.polyDegree);
        string params_object_name  = string("seal-params-") + std::to_string(_enc_init_params.polyDegree);

        if(_read_keys_from_file)
        {
            std::fstream file_parms_fhe2(params_object_name, std::ios::in | std::ios::binary);
            if (file_parms_fhe2.is_open())
            {
                parms.load(file_parms_fhe2);
                file_parms_fhe2.close();
            }
            else throw std::runtime_error("Unable to open file seal-params");

            seal_ptr = srvProtocol.gen_seal_params(parms.poly_modulus_degree(), parms.coeff_modulus(), _enc_init_params.scale);

            //loading pk
            std::fstream file_pk_fhe2(pk_object_name, std::ios::in | std::ios::binary);
            if (file_pk_fhe2.is_open())
            {
                pk_fhe.load(seal_ptr->context_ptr, file_pk_fhe2);
                file_pk_fhe2.close();
            }
            else throw std::runtime_error("Unable to open file pk-fhe");

            seal_ptr->encryptor_ptr = make_shared<Encryptor>(seal_ptr->context_ptr, pk_fhe);

        }
        else
        {

            if (!utility::GetEncryptionParamsFromBucket(params_object_name, awsparams::bucket_name, awsparams::region,
                                                        parms)) {
                std::cerr << "Failed to get public key";
                return;
            }
            seal_ptr = srvProtocol.gen_seal_params(parms.poly_modulus_degree(), parms.coeff_modulus(), _enc_init_params.scale);
            cout << " generated seal" << endl;
            if (!utility::GetPublicKeyFromBucket(pk_object_name, awsparams::bucket_name, awsparams::region,
                                                 seal_ptr->context_ptr, pk_fhe)) {
                std::cerr << "Failed to get public key from bucket";
                return;
            }
            seal_ptr->encryptor_ptr = make_shared<Encryptor>(seal_ptr->context_ptr, pk_fhe);

        }

        // Get encrypted batch from bucket
        int buffer_size = double_size * _data_points_num; // each buffer has a size that matches the amount of input data points
        int mac_buff_size_sq = (_batched_size > 0) ? std::ceil(_data_points_num / _batched_size) * double_size : buffer_size;

        // buffers for storing the data read from the bucket
        char* buffer_ct_x_int_frac = new char[buffer_size];
        buffer_tag_sq = new char[mac_buff_size_sq];

        // list for holding the data info to be loaded from the bucket
        buffer_data_vec load_from_bucket_list;

        // file names
        string secret_file_name(CIPHERTEXTS_X_INT_FRAC_DIR);
        string tags_sq_file_name(TAGS_SQ_DIR);

        // create list for info loaded from the bucket
        // each item in the list includes a buffer pointer, the buffer size and the file to read from

        // add secret share buffer to list
        bucket_data secret_share_data;
        secret_share_data.buffer = buffer_ct_x_int_frac;
        secret_share_data.buffer_size = buffer_size;
        secret_share_data.file_name = secret_file_name;
        secret_share_data.parse_func = &Auxiliary_Server::parse_double_into_secret_share;
        secret_share_data.num_of_parsed_items = 2;
        secret_share_data.item_size = double_size;
        load_from_bucket_list.push_back(secret_share_data);

        // add mac buffers to the list
        if(_with_mac)
        {
            bucket_data sq_data;

            sq_data.buffer = buffer_tag_sq;
            sq_data.buffer_size = mac_buff_size_sq;
            sq_data.file_name = tags_sq_file_name;
            sq_data.parse_func = (_batched_size > 0) ? &Auxiliary_Server::parse_double_into_mac_batched_part1 : &Auxiliary_Server::parse_double_into_mac;
            sq_data.num_of_parsed_items = (_batched_size > 0) ? 1 : 3;
            sq_data.item_size = sizeof(double);

            // add mac buffer to the list
            load_from_bucket_list.push_back(sq_data);

            // in batched there are additional mac parameters
            // also, a different parsing function is needed for sq
            if (_batched_size > 0)
            {
                string tags_sr_file_name(TAGS_SR_DIR);
                int mac_buff_size_sr = ceil(_data_points_num / _batched_size) * sizeof(char);
                bucket_data sr_data;
                buffer_tag_sr = new char[mac_buff_size_sr];
                sr_data.buffer = buffer_tag_sr;
                sr_data.buffer_size = mac_buff_size_sr;
                sr_data.file_name = tags_sr_file_name;
                sr_data.parse_func = &Auxiliary_Server::parse_double_into_mac_batched_part2;
                sr_data.num_of_parsed_items = 2;
                sr_data.item_size = sizeof(char);


                load_from_bucket_list.push_back(sr_data);
            }
        }

        high_resolution_clock::time_point start_loading = utility::timer_start();

        for(i = 0; i < load_from_bucket_list.size(); i++)
        {
            // load from buffer - get buffer pointer, buffer size and filename to read from
            load_buffer_from_bucket(s3Utility, load_from_bucket_list[i].buffer, load_from_bucket_list[i].buffer_size, load_from_bucket_list[i].file_name);
        }

        performanceMetrics.load_stored_data += utility::timer_end(start_loading).count();

        num_of_ct = (_data_points_num / _enc_init_params.max_ct_entries) + (((_data_points_num % _enc_init_params.max_ct_entries) > 0)? 1 : 0);
        num_of_mac_ct = (_batched_size > 0) ?  std::ceil(((double)_data_points_num / _batched_size) / _enc_init_params.max_ct_entries) : num_of_ct;


        remaining_data_points_num = _data_points_num;

        for (i = 0; i < num_of_ct; i++)
        {
            std::vector<std::vector<double>> enc_vector_list;

            std::vector<double> x_int_vec;
            std::vector<double> x_frac_vec;
            std::vector<double> sq_vec1;
            std::vector<double> sq_vec2;
            std::vector<double> sq_vec3;

            enc_vector_list.push_back(x_int_vec);
            enc_vector_list.push_back(x_frac_vec);
            if (_with_mac && (num_of_mac_ct > 0))
            {
                enc_vector_list.push_back(sq_vec1);
                enc_vector_list.push_back(sq_vec2);
                enc_vector_list.push_back(sq_vec3);
                num_of_mac_ct--;
            }

            // at this point we have 1 or 2 buffers (depending on with or without mac selection) in the load_from_bucket_list vector
            // we now need to split them into vectors to later be encrypted.
            // Each vector contains the following set of sub-vectors:
            // an int vector and frac vector for the secret share and zr, zy and zq for each of the macs
            // These should be sufficient to reconstruct and verify an amount of number equal or lower than the maximum amount of packed values in the ciphertext

            high_resolution_clock::time_point start_extract_double = utility::timer_start();

            k = 0;
            for(int list_iter = 0; list_iter < load_from_bucket_list.size(); list_iter++)
            {
                // verify the buffer index doesn't exceed the buffer size.
                // this is useful for cases where not all buffers have the same length
                // In batched mode, the mac buffers are shorter and should only be loaded once
                int curr_buff_index = (i * _enc_init_params.max_ct_entries ) * load_from_bucket_list[list_iter].item_size;

                if (curr_buff_index < load_from_bucket_list[list_iter].buffer_size)
                {
                    // load the items from the bucket and parse them into doubles
                    for (j = 0;j < std::min(remaining_data_points_num, _enc_init_params.max_ct_entries) ; j++)
                    {
                            char tempChar = 0;
                            double tempDouble = 0;
                            // calculate the index in the char buffer and extract the double value
                            buffer_index = ((i * _enc_init_params.max_ct_entries + j)) * load_from_bucket_list[list_iter].item_size;

                            // in batched mode we use one buffer with "double" values and one with "char" values.
                            // unfortunately, memcpy from sizeof(char) to tempDouble resulted in bogus values
                            // so in case we need to copy from sizeof(char), we place the value in a char variable and then convert to double
                            if (load_from_bucket_list[list_iter].item_size == sizeof(char))
                            {
                                std::memcpy(&tempChar, load_from_bucket_list[list_iter].buffer + buffer_index, load_from_bucket_list[list_iter].item_size);
                                tempDouble = double(tempChar);
                            }
                            else
                            {
                                std::memcpy(&tempDouble, load_from_bucket_list[list_iter].buffer + buffer_index, load_from_bucket_list[list_iter].item_size);
                            }
                            // parse the double into secret share/mac values
                            auto fptr = load_from_bucket_list[list_iter].parse_func;
                            (this->*fptr)(floor(tempDouble), enc_vector_list, k);
                    }

                    k += load_from_bucket_list[list_iter].num_of_parsed_items;

                    performanceMetrics.load_stored_data += utility::timer_end(start_extract_double).count();
                }

            }
            remaining_data_points_num -= j;

            // optimization for unbatched data
            if (_batched_size == 0)
            {
                // calculate sq_tr and sr_tr values
               std::vector<double> sq_tr_vec(enc_vector_list[ENC_VEC_SQ_ZR_IDX].size(), 0);
               enc_vector_list.push_back(sq_tr_vec);
               //enc_vector_list.push_back(sr_tr_vec);

               // calc SQ_TR values
               // this is zr*p:
               std::transform(enc_vector_list[ENC_VEC_SQ_ZR_IDX].begin(), enc_vector_list[ENC_VEC_SQ_ZR_IDX].end(), enc_vector_list[ENC_VEC_SQ_TR_IDX].begin(), std::bind(std::multiplies<double>(), std::placeholders::_1, (double)_enc_init_params.prime));

               // this is addition of yr
               std::transform(enc_vector_list[ENC_VEC_SQ_TR_IDX].begin(), enc_vector_list[ENC_VEC_SQ_TR_IDX].end(), enc_vector_list[ENC_VEC_SQ_YR_IDX].begin(), enc_vector_list[ENC_VEC_SQ_TR_IDX].begin(), std::plus<double>());

               // now remove the vectors we don't need to send: zr, yr
               // note that the removal needs to be done from the last item to the first
               // in order to use the indikces in the enum
               //enc_vector_list.erase(enc_vector_list.begin()+ENC_VEC_SR_YR_IDX);
               //enc_vector_list.erase(enc_vector_list.begin()+ENC_VEC_SR_ZR_IDX);
               enc_vector_list.erase(enc_vector_list.begin()+ENC_VEC_SQ_YR_IDX);
               enc_vector_list.erase(enc_vector_list.begin()+ENC_VEC_SQ_ZR_IDX);
            }

            // now we encrypt and send the data
            for (k=0; k < enc_vector_list.size(); k++)
            {
                // encode, encrypt and serialize
                string serialized_str = EncodeEncryptSerialize(enc_vector_list[k], seal_ptr, &performanceMetrics);

                high_resolution_clock::time_point send_data = utility::timer_start();

                // send the length of the serialized str so the client will know the buffer size to expect
                ullong ser_str_len = serialized_str.length();
                std::ostringstream oss;
                oss << ser_str_len;
                char csize_arr[sizeof(ullong) + 1] = {0};
                memcpy(csize_arr, oss.str().c_str(), oss.str().length());

                // log sent size
                performanceMetrics.sent_size_in_bytes += sizeof(ullong);

                sent = 0;
                sent_times = 0;
                while ((sent == 0) && (sent_times < MAX_SOCKET_SEND_RETRIES))
                {
                    sent = send(the_socket, csize_arr, sizeof(ullong), 0);
                    sent_times++;
                }
                if (sent_times == MAX_SOCKET_SEND_RETRIES)
                {
                    perror("Failed sending size over socket\n");
                    exit(1);
                }


                /*
                ullong chunk_size = 1024;
                int sent = 0;
                char* char_array = new char[ser_str_len + 1];
                strcpy(char_array, serialized_str.c_str());
                char *p = char_array;
                ullong remaining = ser_str_len;
                int n;
                // next send the serialized string
                for (n = 0; n < serialized_str.length();  n += sent)
                {
                        sent = send(the_socket, p, std::min(chunk_size, remaining), 0);
                        if (sent > 0)
                        {
                            p += sent;
                            remaining -= sent;
                        }
                        else
                        {
                            sent = 0;
                        }
                }*/


                // now send the serialized string
                sent = 0;
                sent_times = 0;
                // log sent size
                performanceMetrics.sent_size_in_bytes += ser_str_len;
                while ((sent == 0) && (sent_times < MAX_SOCKET_SEND_RETRIES))
                {
                    sent = send(the_socket, serialized_str.c_str(), ser_str_len, 0);
                    sent_times++;
                }
                if (sent_times == MAX_SOCKET_SEND_RETRIES)
                {
                    perror("Failed sending data over socket\n");
                    exit(1);
                }

                performanceMetrics.send_data += utility::timer_end(send_data).count();
                //delete[] char_array;
            }
        }

        performanceMetrics.end2end = utility::timer_end(end2end).count();
        // cleanup allocated buffers
        delete buffer_ct_x_int_frac;
        delete buffer_tag_sq;
        //delete buffer_tag_sr;

        *metrics_file << performanceMetrics << endl;
    }
    Aws::ShutdownAPI(options);

}


void Auxiliary_Server::load_buffer_from_bucket(S3Utility& s3_utility, char* buffer, int buffer_size, string file_name){
    file_name.append("/");
    file_name.append(std::to_string(0));
    s3_utility.load_from_bucket(file_name.c_str(), awsparams::bucket_name,
                                buffer_size, buffer);
    cout << "Loading from bucket " << file_name<< endl;
    }


