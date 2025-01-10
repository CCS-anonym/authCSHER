#include <getopt.h>
#include <sys/stat.h>
#include <iostream>
#include "Test_Protocol.h"
#include "../Constants.h"

using namespace seal;
using namespace Aws;

void printHelp(void)
{
    std::cout <<
            "--input <n>:                 Amount of secrets (input size) to generate. Default is: " << constants::DEFAULT_INPUT_SIZE << "\n"
            "--repeat <n>:                Number of times to repeat the input generation. Default is 1\n"
            "--enc_param_file <filename>  Read encryption params from a local file instead of defaults\n"
            "--no_test_mode               Do not validate output\n"
            "--no_mac                     Do not generate message authentication\n"
            "--help                       Display this help message\n";
    exit(1);

}


int main(int argc, char* argv[])
{

    TP_performance_metrics performanceMetrics;
    // command line argument defaults
    bool test_mode = true;
    int input_size = constants::DEFAULT_INPUT_SIZE;
    int repeat_times = 1;
    bool with_mac = true;
    string params_file = "";

    const char* const short_opts = "i:m:e:nth";
    const option long_opts [] =
    {
            {"input", required_argument, nullptr, 'i'},
            {"repeat", required_argument, nullptr, 'm'},
            {"enc_param_file", required_argument, nullptr, 'e'},
            {"no_mac", no_argument, nullptr, 'n'},
            {"no_test_mode", no_argument, nullptr, 't'},
            {"help", no_argument, nullptr, 'h'},
    };

    while (true)
    {
        const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
        if (-1 == opt)
            break;

        switch(opt)
        {
        case 'i':
            input_size = std::stoi(optarg);
            break;

        case 'm':
            repeat_times = std::stoi(optarg);
            break;

        case 'e':
            params_file = optarg;
            break;

        case 'n':
            with_mac = false;
            break;

        case 't':
            test_mode = false;
            break;

        case 'h':
        case '?':
        default:
            printHelp();
            break;

        }

    }

    Test_Protocol test_protocol(params_file);

    // create metrics file
    std::ofstream metrics_file = utility::openMetricsFile(input_size, "TP_");
    metrics_file << TP_performance_metrics::getHeader() << endl;

    shared_ptr<seal_struct> seal = test_protocol.set_seal_struct();

    bool is_sha512 = true;
    for (int i=0; i<repeat_times; i++){
        test_protocol.test_storage_fhe(input_size, seal, performanceMetrics);

        //test_protocol.test_hkdf(performanceMetrics);
        //test_protocol.test_crypto_sink_hmac(performanceMetrics);

        //test_protocol.test_storage_unbatched(input_size, seal, true, performanceMetrics);
        //test_protocol.test_compact_HE_mac_optimized(input_size);
        //test_protocol.test_compact_unbatched_HE_mac(input_size);

        //test for timing test of storage with hmac on fhe ctxt
        //test_protocol.hmac_on_FHE(input_size, seal, performanceMetrics);

        metrics_file << performanceMetrics << endl;
    }



    metrics_file.close();
    cout << "Done\n";

    return 0;
}
