#ifndef CONSTANTS_H
#define CONSTANTS_H

typedef unsigned long long ullong;
typedef long long llong;
typedef unsigned char byte;
const int BLOCK_SIZE_BYTES{ 16 };
const int KEY_SIZE_BYTES{ 32 };
const int MAX_SOCKET_SEND_RETRIES { 15 };

namespace constants
{
    //for secret sharing only:
    constexpr ullong prime = 222863; //18 bit prime, bit sizes {60, 60, 60, 60,60} poly 16384

    constexpr ullong prime_minus_1 = prime - 1;

    inline int polyDegree{ 16384 };
    inline int MAX_CT_ENTRIES = polyDegree / 2;
    inline int DEFAULT_INPUT_SIZE = 16; // define as 1 for unbatched, or larger for batched protocol
    inline int NUM_DATAPOINTS_IN_BLOCK = 16000000;
    const inline double SCALE{ pow(2.0, 60) };

    //inline std::vector<int> bit_sizes({55, 55, 55, 55,55});
    inline std::vector<int> bit_sizes({60,60,60,60,60});

    //inline std::vector<int> bit_sizes({60, 45, 45, 45, 60});

    inline std::string SECRET_SHARE_KEY_FILENAME("key_DS.txt");

    inline std::string TAG_SQ_KEY_FILENAME("key_sq.txt");
    inline std::string TAG_SR_KEY_FILENAME("key_sr.txt");


    const inline int SECURITY_PARAM = 40; //number of security bits of security parameter
    const inline int N = 1;
    //const inline int MAC_REPS = ceil(SECURITY_PARAM / log2(prime / N)); //k is number of repetitions to do MAC.
    const inline int MAC_REPS=1;

    const int max_reported_incorrect_items = 10; // max number of mac and secret share discrepancies to report

    const std::string MAC_DERIVE_KEY = "storage_test_MAC_";
    const std::string SECRET_SHARE_DERIVE_KEY = "storage_test_";

}



#endif
