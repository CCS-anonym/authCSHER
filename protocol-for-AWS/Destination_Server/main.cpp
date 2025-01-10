#include <getopt.h>
#include "Destination_Server.h"

void printHelp(void)
{
    std::cout <<
            "--input <n>                          Number of secret values to transfer\n"
            "--ip <ip_addr>                       Aux server IP address. Default is localhost\n"
            "--enc_param_file <filename>          Read encryption params from a local file instead of defaults\n"
            "--read_keys_from_file                Read encryption keys from a local file instead of s3 bucket\n"
            "--read_keys_from_s3                  Read keys from amazon s3 bucket\n"
            "--no_mac                             Do not read message authentication\n"
            "--batched                            Batched MAC\n"
            "--repeat_times <n>                   Number of times to repeat the reading. Default is 1\n"
            "--no_test_mode                       Do not validate output\n"
            "--read_secret_from_file              In test mode, read the secret numbers from a file. Default is to read from the bucket\n"
            "--square_diff                        Perform square diff on the MAC verification out\n"
            "--help                               Display this help message\n";
    exit(1);

}


int main(int argc, char* argv[])
{
    // default command line argument values
    bool read_keys_from_file = false;
    bool read_keys_from_s3 = false;
    bool read_secret_from_file = false;
    bool gen_new_keys = false;
    bool with_mac = true;
    bool test_mode = true;
    bool square_diff = false;
    bool batched = false;
    string server_ip = "127.0.0.1";
    string params_file = "";
    int data_points_num = constants::DEFAULT_INPUT_SIZE;
    int repeatTimes = 1;

    const char* const short_opts = "i:p:e:m:rsntfh";
    const option long_opts [] =
    {
            {"input", required_argument, nullptr, 'i'},
            {"ip",    required_argument, nullptr, 'p'},
            {"enc_param_file", required_argument, nullptr, 'e'},
            {"repeat_times", required_argument,nullptr, 'm'},
            {"read_keys_from_file", no_argument, nullptr, 'r'},
            {"read_keys_from_s3", no_argument, nullptr, 's'},
            {"no_mac", no_argument, nullptr, 'n'},
            {"batched", no_argument, nullptr, 'b'},
            {"no_test_mode", no_argument, nullptr, 't'},
            {"read_secret_from_file", no_argument, nullptr, 'f'},
            {"square_diff", no_argument, nullptr, 'q'},
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
            data_points_num = std::stoi(optarg);
            break;

        case 'r':
            read_keys_from_file = true;
            if (read_keys_from_s3 == true)
            {
                cout << "only one options read_keys_from_s3 or read_keys_from_file can be specified" << endl;
                exit(0);
            }
            break;

        case 's':
            read_keys_from_s3 = true;
            if (read_keys_from_file == true)
            {
                cout << "only one options read_keys_from_s3 or read_keys_from_file can be specified" << endl;
                exit(0);
            }
            break;

        case 'm':
            repeatTimes = std::stoi(optarg);
            break;

        case 'p':
            server_ip = optarg;
            break;

        case 'e':
            params_file = optarg;
            break;

        case 'f':
            read_secret_from_file = true;
            break;

        case 't':
            test_mode = false;
            break;

        case 'n':
            with_mac = false;
            break;

        case 'b':
            batched = true;
            break;

        case 'q':
            square_diff = true;
            break;

        case 'h':
        case '?':
        default:
            printHelp();
            break;

        }

    }

    gen_new_keys = !(read_keys_from_file || read_keys_from_s3);

    Destination_Server dest_server(data_points_num, batched, params_file, square_diff);

    dest_server.GetEncryptionParams(read_keys_from_file, read_keys_from_s3, with_mac);
    dest_server.RequestAndParseDataFromAux(repeatTimes, server_ip, with_mac,test_mode, read_secret_from_file);
}
