#pragma once
#include "seal/seal.h"
#include "../Servers_Protocol.h"
#include "cpprest/http_listener.h"
#include "../Utility.h"

using namespace utility;

using std::cout;
using std::endl;
using std::string;


/**
Batched optimization - AS encrypts the following:
ctxt1: y_t_ct = y_alpha_frac*p^2 + y_beta_frac*p + y_r
ctxt2: y_alpha_int_ct
ctxt3: y_beta_int_ct
**/

class AS_performance_metrics
{
public:
    long long end2end = 0;
    long long write_request_to_stream = 0;
    long long load_as_key = 0;
    long long load_stored_data = 0;
    long long encode_encrypt = 0;
    long long serialize = 0;
    long long sent_size_in_bytes = 0;
    long long send_data = 0;

    static std::string getHeader();
};

std::ostream& operator<<(std::ostream&, const AS_performance_metrics& asPerformanceMetrics);

enum enc_vec_list_index
{
    ENC_VEC_X_INT_IDX = 0,
    ENC_VEC_X_FRAC_IDX,
    ENC_VEC_SQ_ZR_IDX,
    ENC_VEC_SQ_YR_IDX,
    ENC_VEC_SQ_ZQ_IDX,
    //ENC_VEC_SR_ZR_IDX,
    //ENC_VEC_SR_YR_IDX,
    //ENC_VEC_SR_ZQ_IDX,
    ENC_VEC_SQ_TR_IDX,
    //ENC_VEC_SR_TR_IDX
};

enum enc_vec_list_batched_index
{
    ENC_VEC_BATCHED_X_INT_IDX = 0,
    ENC_VEC_BATCHED_X_FRAC_IDX,
    ENC_VEC_BATCHED_SQ_TR_IDX,
    ENC_VEC_BATCHED_SR_ALPHA_INT_IDX,
    ENC_VEC_BATCHED_SR_BETA_INT_IDX,
};

class Auxiliary_Server : public Servers_Protocol //to inherit generating SEAL params
{

private:
    int _data_points_num;
    bool _read_keys_from_file;
    bool _with_mac;
    enc_init_params_s _enc_init_params;
    int _batched_size;

    tuple<const shared_ptr<vector<std::string>>, const shared_ptr<vector<std::string>>> ProcessAndEncrypt(S3Utility& s3_utility, const shared_ptr<seal_struct> seal, AS_performance_metrics *performanceMetrics);

    void ProcessAndEncryptWithMAC(S3Utility& s3_utility, const shared_ptr<seal_struct> seal, AS_performance_metrics *performanceMetrics);
    void SetupServerSocket(int &server_socket);
    void AcceptConnections(int server_socket);
    inline shared_ptr<vector<double>> FillVecByCTSize(std::vector<double>::iterator start, int ct_index);
    inline shared_ptr<vector<double>> FillVecByInputSize(std::vector<double>::iterator start, int ct_index);
    inline string EncodeEncryptSerialize(vector<double> &vec, const shared_ptr<seal_struct> seal, AS_performance_metrics *performanceMetrics);
    void parse_double_into_secret_share(double val, std::vector<std::vector<double>>& enc_vector_list, long index);
    void parse_double_into_mac(double val, std::vector<std::vector<double>>& enc_vector_list, long index);
    void parse_double_into_mac_batched_part1(double val, std::vector<std::vector<double>>& enc_vector_list, long index);
    void parse_double_into_mac_batched_part2(double val, std::vector<std::vector<double>>& enc_vector_list, long index);


public:
    std::ofstream *metrics_file;
    std::ostringstream os;

    Auxiliary_Server(int data_points_num, bool read_keys_from_file, bool with_mac, bool batched, string enc_init_params_file, std::ofstream *metrics_file_in);
    ~Auxiliary_Server() {}
    Auxiliary_Server(const Auxiliary_Server& auxiliaryServer) {} //copy c'tor
    void StartServer(void);
    void EncryptAndSendData(int the_socket);
    void load_buffer_from_bucket(S3Utility& s3_utility,char* buffer, int buffer_size, string file_name);


};


// a struct for holding information about the data to be read from the bucket
struct bucket_data {
	char* buffer;  // the buffer to read data into
	int buffer_size; // the size of the data to be read
	string file_name; // the file name to read from
	void(Auxiliary_Server::* parse_func)(double, std::vector<std::vector<double> >&, long int);  // the function used to parse the data
	int num_of_parsed_items; // the number of doubles extracted by the parsing function
	int item_size; // the size of each item in the buffer
};
