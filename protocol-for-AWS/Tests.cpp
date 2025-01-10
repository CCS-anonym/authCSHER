#include "Tests.h"


int tests::is_correct_secret_sharing(shared_ptr<vector<Ciphertext>> x_final_CT, shared_ptr<seal_struct> seal, const vector<double>& x_origin,
                                     int input_size, int max_ct_entries)
{
    int fhe_ctxt_number = ceil((input_size + 0.0) / max_ct_entries); //number of FHE  ciphertexts, derived automatically from user input

    vector<vector<double>> main_final_x;

    cout << "Checking secret share correctness" << endl;
	//decrypt and decode final output
	for (int i = 0; i < fhe_ctxt_number; i++)
	{
		Plaintext plain;
		vector<double> final_x;
		seal->decryptor_ptr->decrypt(x_final_CT.get()->at(i), plain);
		seal->encoder_ptr->decode(plain, final_x);
		main_final_x.push_back(final_x);
	}
	//check if output equals input
	int counter_incorrect =0;
	int threshold = 1;
	for (int i = 0; (i < fhe_ctxt_number); i++)
	{
        for (int j = 0; j < max_ct_entries && ((j + i * max_ct_entries) < input_size) && (counter_incorrect < constants::max_reported_incorrect_items); j++)
		{
		    double orig_val = x_origin[j + i * max_ct_entries];
		    double calc_val = main_final_x[i][j];

            if (abs(orig_val - calc_val) > threshold){
                cout << "incorrect " << endl;
				counter_incorrect++; //in case of final digit affects intire num
				cout << "CT index is: " << i << " datapoint index " << j << " origin is " << orig_val << " result is " << calc_val << endl;
			}

		}
	}

	if (counter_incorrect > 0)
    {
        cout << "Secret share incorrect count: " << counter_incorrect << endl;
        if (counter_incorrect >= constants::max_reported_incorrect_items)
        {
            cout << "Note that incorrect amounts larger than " << constants::max_reported_incorrect_items << " will not be reported" << endl;
        }
    }
    else
    {
        cout << "Secret share check for " << input_size << " inputs - PASSED!" << endl;
    }

	return 1;
}



bool tests::is_MAC_HE_valid(shared_ptr<seal_struct> seal_struct, shared_ptr<vector<Ciphertext>> diffCt, int input_size, int max_ct_entries, string mac_type, bool compactMac)
{

    int fhe_ctxt_number = ceil((input_size + 0.0) / max_ct_entries); //number of FHE  ciphertexts, derived automatically from user input
    if(compactMac){
        fhe_ctxt_number =1;
    }

    bool correct = true;
    int EPSILON = 1;
    int counter_incorrect = 0;

    cout << "Checking " << mac_type << " MAC correctness" << endl;
    //decrypt and decode output for comparison on cleartext
    for (int i = 0; i < fhe_ctxt_number; i++)
	{
        Plaintext pt_diff;
        vector<double> diff_vec;
        seal_struct->decryptor_ptr->decrypt(diffCt.get()->at(i), pt_diff);
        seal_struct->encoder_ptr->decode(pt_diff, diff_vec);


        for (int j = 0; (j < max_ct_entries) && ((j + i * max_ct_entries) < input_size) && (counter_incorrect < constants::max_reported_incorrect_items);  j++) {
            bool equal = (abs(diff_vec[j]) < EPSILON);
            //cout <<"diff_vec[j]: "<<diff_vec[j]<<endl;
            if (equal != true)
            {
                cout.precision(14);
                std::cout << " ERROR at cipher: "<<i <<" index "<< j << " diff is: " << diff_vec[j] << endl;
                correct = false;
                counter_incorrect+=1;
            }
        }
	}

    if (counter_incorrect > 0)
    {
        cout << "MAC incorrect count: " << counter_incorrect << endl;
        if (counter_incorrect >= constants::max_reported_incorrect_items)
        {
            cout << "Note that incorrect amounts larger than " << constants::max_reported_incorrect_items << " will not be reported" << endl;
        }
    }
    else
    {
        cout << "MAC check for " << input_size << " inputs - PASSED!" << endl;
    }


    return correct;
}


bool tests::is_MAC_PT_valid(vector<double> diff_vec, int input_size, int max_ct_entries, string mac_type)
{

    int fhe_ctxt_number = ceil((input_size + 0.0) / max_ct_entries); //number of FHE  ciphertexts, derived automatically from user input
    bool correct = true;
    int EPSILON = 1;
    int counter_incorrect = 0;

    cout << "Checking " << mac_type << " MAC correctness" << endl;
    for (int i = 0; i < fhe_ctxt_number; i++)
	{

        for (int j = 0; (j < max_ct_entries) && ((j + i * max_ct_entries) < input_size) && (counter_incorrect < constants::max_reported_incorrect_items);  j++) {
            bool equal = (abs(diff_vec[j]) < EPSILON);
            //cout <<"diff_vec[j]: "<<diff_vec[j]<<endl;
            if (equal != true)
            {
                cout.precision(14);
                std::cout << " ERROR at cipher: "<<i <<" index "<< j << " diff is: " << diff_vec[j] << endl;
                correct = false;
                counter_incorrect+=1;
            }
        }
	}

    if (counter_incorrect > 0)
    {
        cout << "MAC incorrect count: " << counter_incorrect << endl;
        if (counter_incorrect >= constants::max_reported_incorrect_items)
        {
            cout << "Note that incorrect amounts larger than " << constants::max_reported_incorrect_items << " will not be reported" << endl;
        }
    }
    else
    {
        cout << "MAC cleartext check passed for " << input_size << " inputs" << endl;
    }


    return correct;
}


void tests::test_crypto_sink(){


    const byte k[] = {
      0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,
      0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,
      0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,
      0x1,0x1
    };

    string plain = "HMAC3333333333333333333";
    string mac, encoded;

    /*********************************\
    \*********************************/

    // Pretty print key
    encoded.clear();
    CryptoPP::StringSource ss1(k, sizeof(k), true,
        new HexEncoder(new StringSink(encoded)) ); // HexEncoder StringSource

    cout << "key: " << encoded << endl;
    cout << "plain text: " << plain << endl;

    /*********************************\
    \*********************************/

    nanoseconds hmac_time, final_hmac_time;
    for(int i=0; i<10; i++){

        try
        {
            high_resolution_clock::time_point init_hmac = utility::timer_start();
            CryptoPP::HMAC< SHA256 > hmac(k, sizeof(k));
            hmac_time = utility::timer_end(init_hmac);

            high_resolution_clock::time_point update_hmac = utility::timer_start();
            StringSource ss2(plain, true,
                new HashFilter(hmac, new StringSink(mac) ) ); // HashFilter// StringSource
            final_hmac_time = utility::timer_end(update_hmac);

            cout << "hmac len : "<<mac.size()<< " data: " << mac << endl;

        }
        catch(const CryptoPP::Exception& e)
        {
            std::cerr << e.what() << endl;
            exit(1);
        }
        cout<<"hmac_time: " <<hmac_time.count() <<" final_hmac_time " << final_hmac_time.count()<<endl;
        mac.clear();
    }

    /*********************************\
    \*********************************/

    // Pretty print
    encoded.clear();
    StringSource ss3(mac, true,
        new HexEncoder( new StringSink(encoded)) ); // HexEncoder // StringSource

    cout << "hmac len : "<<encoded.size()<< " data: " << encoded << endl;
}



void tests::test_hmac_cryptopp(){

    AutoSeededRandomPool prng;

    SecByteBlock key(16);
    prng.GenerateBlock(key, key.size());

    string plain = "HMAC Test";
    string mac, encoded;

    /*********************************\
    \*********************************/

    // Pretty print key
    encoded.clear();
    StringSource ss1(key, key.size(), true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource

    cout << "key: " << encoded << endl;
    cout << "plain text: " << plain << endl;

    /*********************************\
    \*********************************/

    try
    {
        HMAC< SHA256 > hmac(key, key.size());

        StringSource ss2(plain, true,
            new HashFilter(hmac,
                new StringSink(mac)
            ) // HashFilter
        ); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << endl;
        exit(1);
    }

    /*********************************\
    \*********************************/

    // Pretty print
    encoded.clear();
    StringSource ss3(mac, true,
        new HexEncoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource

    cout << "hmac: " << encoded << endl;

    try
    {
        HMAC< SHA256 > hmac(key, key.size());
        const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;

        StringSource(plain + mac, true,
            new HashVerificationFilter(hmac, NULL, flags)
        ); // StringSource

        cout << "Verified message" << endl;
    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << endl;

    }

}







