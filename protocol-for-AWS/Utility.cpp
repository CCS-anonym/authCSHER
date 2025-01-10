#include "Utility.h"
#include <sstream>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/PutObjectRequest.h>

using namespace Aws;

#define LINE_SIZE 100 //to read csv file
#define ROW_NUM 16 // in csv


S3Utility::S3Utility(const Aws::String& region){
    Aws::Client::ClientConfiguration config;
    config.region = region;
    Aws::S3::S3Client s3_client(config);
    m_s3_client = s3_client;
}

const bool S3Utility::load_from_bucket(const Aws::String& objectKey, const Aws::String& fromBucket, int size, char* buffer){    //cout << objectKey << " " << fromBucket << " " << region << " " << size << endl;

    Aws::S3::Model::GetObjectRequest object_request;

    object_request.SetBucket(fromBucket);
    object_request.SetKey(objectKey);

    //high_resolution_clock::time_point start_loading = utility::timer_start();

    Aws::S3::Model::GetObjectOutcome get_object_outcome =
            m_s3_client.GetObject(object_request);

    //nanoseconds loading_time = utility::timer_end(start_loading);
    //cout << "Time to get object " << loading_time.count() << endl;

    if (get_object_outcome.IsSuccess())
    {
        Aws::IOStream& out = get_object_outcome.GetResultWithOwnership().GetBody();
        out.read(buffer, size);
        return true;
    }
    else
    {
        auto err = get_object_outcome.GetError();
        std::cout << "Error: GetObject: " <<
                  err.GetExceptionName() << ": " << err.GetMessage() << std::endl;

        return false;
    }

}

const bool S3Utility::save_to_bucket(const Aws::String& object_key, const Aws::String& to_bucket, std::string buffer){

    Aws::S3::Model::PutObjectRequest request;
    request.SetBucket(to_bucket);
    request.SetKey(object_key);

    std::shared_ptr <Aws::IOStream> input_data =
            Aws::MakeShared<Aws::StringStream>("SampleAllocationTag", buffer,
                                               std::ios_base::in | std::ios_base::binary);

    request.SetBody(input_data);

    Aws::S3::Model::PutObjectOutcome outcome = m_s3_client.PutObject(request);

    if (outcome.IsSuccess()) {

        std::cout << "Added object '" << object_key << "' to bucket '"
                  << to_bucket << "'." << endl;
        //return true;
    } else {
        std::cout << "Error: PutObject: " <<
                  outcome.GetError().GetMessage() << std::endl;

        return false;
    }
    return true;
}

//gets number of blovks, location = how many blocks to jump backwards in order to store input
void utility::save_to_file(const char* file_name, size_t no_blocks,  const char* stream)
{
    //cout << "File " << file_name << endl;
    std::ofstream file(file_name, std::ios::binary);
    if (!file.write(stream, no_blocks * BLOCK_SIZE_BYTES))
        throw std::runtime_error("Unable to open");
    file.close();
}
//gets number of blocks, location = how many blocks to jump backwards in order to load input
void utility::load_from_file(std::string file_name, size_t no_blocks, char* stream)
{
    std::ifstream file(file_name, std::ios::binary);
    file.seekg(0, std::ios::beg); // setting ptr of file x block bytes start from the EOF -
    //cout << "Reading " << no_blocks << "\n";
    if (!file.read(stream, no_blocks * BLOCK_SIZE_BYTES)) {      //reading final BYTES from the file
        throw std::runtime_error("Unable to read " + file_name);
    }
    file.close();
}

void utility::load_from_file(std::string file_name, char* stream) {
	std::ifstream iFile(file_name, std::ios::binary);
	iFile.seekg(0, std::ios::beg); // setting ptr of file x block bytes start from the EOF -
	int i = 0;
	cout <<"Opend file\n";
	while (true) {
		if (iFile.eof()) break;
		iFile >> stream[i];
		i++;
	}
	std::cout << "i is: " << i << endl;
	iFile.close();

}

bool utility::GetEncryptionParamsFromBucket(const Aws::String& objectKey, const Aws::String& fromBucket, const Aws::String& region, EncryptionParameters& parms)
{
    Aws::Client::ClientConfiguration config;

    if (!region.empty())
    {
        config.region = region;
    }

    Aws::S3::S3Client s3_client(config);

    Aws::S3::Model::GetObjectRequest object_request;
    object_request.SetBucket(fromBucket);
    object_request.SetKey(objectKey);

    Aws::S3::Model::GetObjectOutcome get_object_outcome =
            s3_client.GetObject(object_request);

    if (get_object_outcome.IsSuccess())
    {
        Aws::IOStream& out = get_object_outcome.GetResultWithOwnership().GetBody();
        cout << "Got params from S3" << endl;
        parms.load(out);
        cout << "Loaded params " << endl;
        return true;
    }
    else
    {
        auto err = get_object_outcome.GetError();
        std::cout << "Error: GetObject: " <<
                  err.GetExceptionName() << ": " << err.GetMessage() << std::endl;

        return false;
    }
}

bool utility::GetPublicKeyFromBucket(const Aws::String& objectKey, const Aws::String& fromBucket, const Aws::String& region, SEALContext context_ptr, seal::PublicKey& pk_fhe)
{
    Aws::Client::ClientConfiguration config;

    if (!region.empty())
    {
        config.region = region;
    }

    Aws::S3::S3Client s3_client(config);

    Aws::S3::Model::GetObjectRequest object_request;
    object_request.SetBucket(fromBucket);
    object_request.SetKey(objectKey);

    Aws::S3::Model::GetObjectOutcome get_object_outcome =
            s3_client.GetObject(object_request);

    if (get_object_outcome.IsSuccess())
    {
        Aws::IOStream& out = get_object_outcome.GetResultWithOwnership().GetBody();
        cout << "Got Key from S3" << endl;
        pk_fhe.load(context_ptr, out);
        cout << "Loaded key " << endl;

        return true;
    }
    else
    {
        auto err = get_object_outcome.GetError();
        std::cout << "Error: GetObject public key:" <<
                  err.GetExceptionName() << ": " << err.GetMessage() << std::endl;

        return false;
    }
}

bool utility::GetSecretKeyFromBucket(const Aws::String& objectKey, const Aws::String& fromBucket, const Aws::String& region, SEALContext context_ptr, SecretKey& sk_fhe)
{
    Aws::Client::ClientConfiguration config;

    if (!region.empty())
    {
        config.region = region;
    }

    Aws::S3::S3Client s3_client(config);

    Aws::S3::Model::GetObjectRequest object_request;
    object_request.SetBucket(fromBucket);
    object_request.SetKey(objectKey);

    Aws::S3::Model::GetObjectOutcome get_object_outcome =
            s3_client.GetObject(object_request);

    if (get_object_outcome.IsSuccess())
    {
        Aws::IOStream& out = get_object_outcome.GetResultWithOwnership().GetBody();
        cout << "Got Key from S3" << endl;
        sk_fhe.load(context_ptr, out);
        cout << "Loaded key " << endl;

        return true;
    }
    else
    {
        auto err = get_object_outcome.GetError();
        std::cout << "Error: GetObject secret key: " <<
                  err.GetExceptionName() << ": " << err.GetMessage() << std::endl;

        return false;
    }
}

void utility::save_fhe_to_file(std::string file_name, Ciphertext ct_input)
{
    std::ofstream file_x_ser(file_name, std::ios::binary);
    if (file_x_ser.is_open())
    {
        ct_input.save(file_x_ser);
        file_x_ser.close();
    }
    else throw std::runtime_error("Unable to open " + file_name);
}

void utility::load_from_fhe_file(std::string file_name, Ciphertext ct_output, SEALContext context)
{
    std::fstream file_x_ser(file_name, std::ios::in | std::ios::binary);
    if (file_x_ser.is_open())
    {
        ct_output.load(context, file_x_ser);
        file_x_ser.close();
    }
    else throw std::runtime_error("Unable to open  " + file_name);
}

std::string utility::serialize_fhe(Ciphertext ct_input)
{
    std::ostringstream os(std::ios::binary);
    ct_input.save(os);
    return os.str();
}


void utility::deserialize_fhe(std::string str, Ciphertext& ct_output, SEALContext& context)
{
    std::istringstream is(str, std::ios::in | std::ios::binary);
    std::streamoff loaded = ct_output.load(context, is);
}

void utility::deserialize_fhe(const char* str, std::size_t size, Ciphertext& ct_output, SEALContext& context)
{
    std::streamoff loaded = ct_output.load(context, (const seal_byte*)str, size);
}

vector<double> utility::x_gen_int(int min, ullong max, ullong amount)// generate random integer x in range
{
    vector<double> random_num_vec;
    ullong i;
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine gen(seed);
    std::uniform_int_distribution<ullong> real_dist(min, max);

    for(i = 0; i < amount; i++)
    {
        random_num_vec.push_back(real_dist(gen));
    }

    return random_num_vec;
}

double utility::x_gen(double min, double max)// generate random x in range
{

    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine gen(seed);
    std::uniform_real_distribution<double> real_dist(0.0, 1.0);
    double x = real_dist(gen);

    return x;
}

std::string utility::derive_rand_key(CryptoPP::HMAC<SHA256> hmac, std::string derivation_data)
{
    std::string mac;
    StringSource ss2(derivation_data, true,
                new HashFilter(hmac, new StringSink(mac) ) ); // HashFilter// StringSource

    if (mac.size() != KEY_SIZE_BYTES){
        throw std::runtime_error("Derivation failed - length not as expected");
    }
    return mac;

}

void utility::derive_rand_key_hkdf(byte* key_tag, int key_tag_len, std::string info, std::vector<byte> &keys, int key_len)
{

    CryptoPP::HKDF<SHA512> hkdf;
    int max_derived_key_len = hkdf.MaxDerivedKeyLength();
    byte derivedKey[max_derived_key_len];

    int num_of_derivations = key_len / max_derived_key_len;
    int remainder = key_len % max_derived_key_len;
    int i = 0;

    for (i = 0; i < num_of_derivations; i++)
    {
        std::string cur_derivation_data = info + std::to_string(i);
        hkdf.DeriveKey(derivedKey, max_derived_key_len, key_tag,  key_tag_len, NULL, 0, (byte *)cur_derivation_data.c_str(), cur_derivation_data.length());
        std::copy(&derivedKey[0], &derivedKey[max_derived_key_len], std::back_inserter(keys));
    }

    if (remainder)
    {
        std::string cur_derivation_data = info + std::to_string(i);
        hkdf.DeriveKey(derivedKey, sizeof(derivedKey), key_tag,  key_tag_len, NULL, 0, derivedKey, max_derived_key_len);
        std::copy(derivedKey, derivedKey+remainder, std::back_inserter(keys));
    }


}


void utility::print_vector(std::vector<double> vec, std::size_t print_size = 4, int prec = 3)
{
	//Save the formatting information for std::cout.
	std::ios old_fmt(nullptr);
	old_fmt.copyfmt(std::cout);

	std::size_t slot_count = vec.size();

//	std::cout << std::fixed << std::setprecision(prec);
	std::cout << std::endl;
	if (slot_count <= 2 * print_size)
	{
		std::cout << "    [";
		for (std::size_t i = 0; i < slot_count; i++)
		{
			std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
		}
	}
	else
	{
		//vec.resize(std::max(vec.size(), 2 * print_size)); //TODO add later
		std::cout << "    [";
		for (std::size_t i = 0; i < print_size; i++)
		{
			std::cout << " " << vec[i] << ",";
		}
		if (vec.size() > 2 * print_size)
		{
			std::cout << " ...,";
		}
		for (std::size_t i = slot_count - print_size; i < slot_count; i++)
		{
			std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
		}
	}
	std::cout << std::endl;

	//Restore the old std::cout formatting.

	std::cout.copyfmt(old_fmt);
}


high_resolution_clock::time_point utility::timer_start()
{
	high_resolution_clock::time_point start0 = high_resolution_clock::now();
	return start0;
}


nanoseconds utility::timer_end(high_resolution_clock::time_point start)
{
	auto stop0 = high_resolution_clock::now();
	auto duration0 = duration_cast<nanoseconds>(stop0 - start);
	return duration0;
}


void utility::send_timer_to_stream(int i, nanoseconds duration, const char* object_name)
{

	glob_str.append(object_name);
	glob_str.append(","); //next excel tab
	glob_str.append(std::to_string(i)); //index
	glob_str.append(",");
	glob_str.append(std::to_string(duration.count())); //time taken
	glob_str.append("\n"); //new excel line

}


void utility::print_timer_excel()
{
	std::ofstream ofs_timer;
	ofs_timer.open("seal-4.1.1-timer.csv");
	ofs_timer << "Function name, Function index ,Time in nanoseconds" << endl;
	ofs_timer << endl;
	ofs_timer << glob_str << endl;
	ofs_timer.close();

}

vector<double> utility::get_vector_from_csv(const char* file_name) {
    cout <<"1"  << "\n";
    char* row_matrix = new char[LINE_SIZE * ROW_NUM];
    get_row_mat(file_name, row_matrix);
    cout <<"2 " << row_matrix << "\n";

    std::vector<double> input_vec;
    for (int i = 0; i < ROW_NUM; i++) {
        cout << i  << " " << std::stod(row_matrix + i*LINE_SIZE) << "\n";
        input_vec.push_back(std::stod(row_matrix + i*LINE_SIZE)); //TODO: fix call
    }

    delete[] row_matrix;
    return input_vec;
}

const char* utility::get_field(char* line, int num)
{
    const char* tok;
    for (tok = strtok(line, ","); //getting all string, seperated by tabs
         tok && *tok;
         tok = strtok(NULL, ",\n")) // final col
    {
        //cout << "tok " << tok << " " << "num " << num << "\n";
        if (!--num) //reading until col index
            return tok; //returning arg number
    }
    cout << "return null\n";
    return NULL;
}

const char* utility::get_row_mat(const char* file_name, char* row_matrix)
{
    FILE* stream = fopen(file_name, "r"); //opens .csv file

    if (stream == NULL) {
        perror("Error opening file");
        exit(1);
    }

    char line[LINE_SIZE];

    for (int i = 0; i < ROW_NUM; i++)
    {
        cout << "1 line " << i << "\n";
        if ((fgets(line, LINE_SIZE, stream) == NULL || line == NULL))
        {
            perror("Error parsing");
            exit(1);
        }
        cout << "2 line " << i << " " << line << "\n";
        //cout << "3 line " << i << " " << get_field(line, 1) << "\n";

        //char* tmp = strdup(line);//copies line and returns copy

        strcpy(row_matrix + LINE_SIZE * i, get_field(line, 1));
        cout << "4 line " << i << "\n";

        printf("matrix %s\n", row_matrix + LINE_SIZE * i); //prints 3rd col in excel file

        //free(tmp);
    }
    return row_matrix;
}


// create folder for metrics file. if it doesn't exist and open metrics file
std::ofstream utility::openMetricsFile(int input_size, string metrics_file_name)
{
    struct stat sb; // used to check if folder exists. not really in use.
    std::string metrics_folder_name("/tmp/out");

    if (stat(metrics_folder_name.c_str(), &sb))
    {
        cout << "Creating folder " << metrics_folder_name << " for metrics" << endl;
        const int dir_err = mkdir(metrics_folder_name.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        if(-1 == dir_err)
        {
            cout << "Error creating folder " << metrics_folder_name << endl;
            exit(1);
        }
    }


    //string metrics_file_name("DO_");
    metrics_file_name += std::to_string(input_size) + ".csv";
    string metrics_file_full_path = metrics_folder_name + "/" + metrics_file_name;

    std::ofstream metrics_file (metrics_file_full_path);
    if (metrics_file.is_open() == 0)
    {
        cout << "Unable to open file " << metrics_file_full_path << endl;
        exit(1);
    }

    return metrics_file;
}

//loading encryption initialization params
void utility::InitEncParams(enc_init_params_s *enc_init_params, string fileName)
{

    // if no file provided, load the defaults.
    if (fileName.empty())
    {
        enc_init_params->prime = constants::prime;
        enc_init_params->prime_minus_1 = constants::prime_minus_1;
        enc_init_params->max_ct_entries = constants::MAX_CT_ENTRIES;
        enc_init_params->polyDegree = constants::polyDegree;
        enc_init_params->bit_sizes = constants::bit_sizes;
        enc_init_params->scale = constants::SCALE;
        enc_init_params->float_precision_for_test = std::to_string(constants::prime).length();
    }
    else // load from file
    {

        std::ifstream inputFile(fileName);
        if (!inputFile)
        {
            throw std::runtime_error("Error:Unable to open file " + fileName);
        }

        string line;
        int line_num = 0;
        while (getline(inputFile, line))
        {
            if (line.empty() || line.at(0) == '#')
                continue;

            std::istringstream iss(line);
            ullong value;

            if (!(iss >> value))
            {
                throw std::runtime_error("Error: Failed to read value from line " + std::to_string(line_num));
            }

            switch(line_num)
            {
                case 0:
                    enc_init_params->prime = value;
                    break;
                case 1:
                    enc_init_params->polyDegree = (int)value;
                    break;
                case 2:
                    enc_init_params->scale = pow(2.0, (int)value);
                    break;
                case 3:
                    enc_init_params->bit_sizes.push_back((int)value);
                    while(iss >> value)
                    {
                        enc_init_params->bit_sizes.push_back((int)value);
                    }
                    break;
                default:
                    throw std::runtime_error("Error: Too many lines in the file");
            }

            line_num++;
        }

        if (line_num < 4)
        {
            throw std::runtime_error("Error: Insufficient lines in the file.");
        }

        inputFile.close();
        enc_init_params->max_ct_entries =enc_init_params->polyDegree / 2;
        enc_init_params->prime_minus_1 = enc_init_params->prime - 1;
        enc_init_params->float_precision_for_test = std::to_string(enc_init_params->prime).length();

        std::cout << "Read the following parameters from " << fileName << ":" << endl;
        std::cout << "prime: " << enc_init_params->prime << " scale: 2^"  << log2(enc_init_params->scale) << " max_ct: " << enc_init_params->max_ct_entries << " polyDegree: " << enc_init_params->polyDegree << " prime_minus_1: " << enc_init_params->prime_minus_1 << " bit sizes:";
        for (int i = 0; i<enc_init_params->bit_sizes.size(); i++)
        {
            cout << " " << enc_init_params->bit_sizes[i];

        }
        cout << endl;

    }
}
