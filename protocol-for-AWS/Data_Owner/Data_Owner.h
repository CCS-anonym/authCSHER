#pragma once
#include "seal/seal.h"
#include "../Servers_Protocol.h"

#define MAX_FILE_NAME 256
using std::cout;  using std::endl;
using std::string;

class DO_performance_metrics
{
public:
    long long share = 0;
    long long mac = 0;
    long long encrypt = 0;
    long long upload_shared = 0;
    long long upload_sq = 0;
    long long upload_sr = 0;
    long long end2end = 0;

    static std::string getHeader();
};

std::ostream& operator<<(std::ostream&, const DO_performance_metrics& doPerformanceMetrics);

class Data_Owner
{
private:
    vector<double> _secret_num_vec;
    enc_init_params_s _enc_init_params;
public:
    Data_Owner(string enc_params_file); // constructor
    ~Data_Owner() {} //class d'tor
    Data_Owner(const Data_Owner& data_owner) {} //copy c'tor
    void GenSecret(ullong input_size);
    int GenSecretShare(DO_performance_metrics& performanceMetrics);
    void SaveSecertToBucket();
    int GenSecretShareAndCompactMAC(DO_performance_metrics& performanceMetrics, bool batched);

};

