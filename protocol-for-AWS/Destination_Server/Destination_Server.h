#pragma once
#include "seal/seal.h"
#include "../Servers_Protocol.h"
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include "DS_Performance_metrics.h"

using std::cout;  using std::endl;

using namespace utility;


std::ostream& operator<<(std::ostream&, const DS_performance_metrics& dsPerformanceMetrics);


enum CT_Index
{
    CT_IDX = 0,
    X_INT_SIZE,
    X_INT_IDX,
    X_FRAC_SIZE,
    X_FRAC_IDX,
    SQ_ZQMSKD_SIZE,
    SQ_ZQMSKD_IDX,
    SQ_TR_SIZE,
    SQ_TR_IDX,

};

enum CT_BATCHED_Index
{
    BATCHED_TR_SIZE = X_FRAC_IDX + 1 ,
    BATCHED_TR_IDX,
    BATCHED_ALPHA_INT_SIZE,
    BATCHED_ALPHA_INT_IDX,
    BATCHED_BETA_INT_SIZE,
    BATCHED_BETA_INT_IDX,
};

enum CT_Max_Index
{
    MAX_IDX_WITHOUT_MAC = 2,
    MAX_IDX_WITH_UNBATCHED_MAC = 4,
    MAX_IDX_WITH_BATCHED_MAC = 5
};


class Destination_Server : public Servers_Protocol //to inherit generating SEAL params
{
private:
    std::vector<double> _secret_vec;
    shared_ptr<seal_struct> _seal;
    enc_init_params_s _enc_init_params;
    int _batched_size;
    std::queue<vector<string>> _ct_queue;
    std::mutex _mutex;

    std::mutex _log_mutex;

    char _DS_key_ch[KEY_SIZE_BYTES];
    char _SQ_key_ch[KEY_SIZE_BYTES];
    char _SR_key_ch[KEY_SIZE_BYTES];

    bool square_diff;
    SHARE_MAC_KEYS _secret_share_keys;
    SHARE_MAC_KEYS _kmac_keys;



    void ProcessCt(DS_performance_metrics* performanceMetrics, bool with_mac);
    bool ReadSecret(bool read_secret_from_file);
    void VerifyAndReconstruct(vector<std::string> str_vec, bool with_mac, DS_performance_metrics *performanceMetrics);

    inline shared_ptr<vector<double>> FillVecByCTSize(std::vector<double>::iterator start, int ct_index);
    inline shared_ptr<vector<double>> FillVecByInputSize(std::vector<double>::iterator start, int ct_index);

public:

    std::ofstream metrics_file;
    int data_points_num;
    int total_num_of_unprocessed_ct;
    int prime_bits_to_bytes;
    vector<Ciphertext> reconstructed_FHE_CT;
    vector<Ciphertext> diff_SQ_FHE_CT, diff_SR_FHE_CT;
    Ciphertext batched_y_ct;
    Ciphertext batched_y_tag_ct;

    CryptoPP::HMAC<CryptoPP::SHA256> hmac;
    CryptoPP::HMAC<CryptoPP::SHA256> hmac_sq;
    CryptoPP::HMAC<CryptoPP::SHA256> hmac_sr;

    Destination_Server(int data_points_num_input, bool batched, string enc_init_params_file, bool squareDiff);//class c'tor
    ~Destination_Server() {} //class d'tor
    //Destination_Server(const Destination_Server& destinationServer) {} //copy c'tor
    bool GetEncryptionParams(bool read_keys_from_file, bool read_keys_from_s3, bool with_mac);
    void RequestAndParseDataFromAux(int repeatTimes, string server_ip, bool with_mac, bool test_mode, bool read_secret_from_file);
    void VerifyOutput(bool read_secret_from_file, bool with_mac);
};
