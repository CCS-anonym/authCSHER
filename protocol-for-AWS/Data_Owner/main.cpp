#include <getopt.h>
#include <sys/stat.h>
#include <iostream>
#include "Data_Owner.h"
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
            "--batched                    Batched MAC\n"
            "--help                       Display this help message\n";
    exit(1);

}


int main(int argc, char* argv[])
{

    DO_performance_metrics performanceMetrics;
    // command line argument defaults
    bool test_mode = true;
    int input_size = constants::DEFAULT_INPUT_SIZE;
    int repeat_times = 1;
    bool with_mac = true;
    bool batched = false;
    string params_file = "";

    const char* const short_opts = "i:m:e:nbth";
    const option long_opts [] =
    {
            {"input", required_argument, nullptr, 'i'},
            {"repeat", required_argument, nullptr, 'm'},
            {"enc_param_file", required_argument, nullptr, 'e'},
            {"no_mac", no_argument, nullptr, 'n'},
            {"batched", no_argument, nullptr, 'b'},
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

        case 'b':
            batched = true;
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

    Data_Owner data_owner(params_file);

    // create metrics file
    std::ofstream metrics_file = utility::openMetricsFile(input_size, "DO_");
    metrics_file << DO_performance_metrics::getHeader() << endl;

    for (int j=0; j< repeat_times; j++)
    {
        high_resolution_clock::time_point end2end = utility::timer_start();
        cout << "Preparing " << input_size << " data points" << endl;

        // generate random secret numbers
        data_owner.GenSecret(input_size);


        if(with_mac){
            if(data_owner.GenSecretShareAndCompactMAC(performanceMetrics, batched)==0){
                std::cerr << "Error generating secret shares and MAC" << endl;
                return 0;
            }
        }
        else{
                  // generate secret share for secret numbers
            if (data_owner.GenSecretShare(performanceMetrics) == 0){
                std::cerr << "Error generating secret shares" << endl;
                return 1;
            }
        }

        performanceMetrics.end2end = utility::timer_end(end2end).count();

        metrics_file << performanceMetrics << endl;

        // For test mode write the original generated numbers in secret_num_vec to the bucket.
        // This is later used by the destination server for comparison and accuracy calculation.
        if (test_mode)
        {
            data_owner.SaveSecertToBucket();
        }
    }
    metrics_file.close();
    cout << "Done\n";
    return 0;
}
