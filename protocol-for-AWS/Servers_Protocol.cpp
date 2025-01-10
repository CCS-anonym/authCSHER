#include "Servers_Protocol.h"


shared_ptr<seal_struct> Servers_Protocol::gen_seal_params(int poly_modulus_degree, vector<int> bit_sizes, double scale) {
    return gen_seal_params(poly_modulus_degree, CoeffModulus::Create(poly_modulus_degree, bit_sizes), scale);
}

shared_ptr<seal_struct> Servers_Protocol::gen_seal_params(int poly_modulus_degree, vector<seal::Modulus> coeff_modulus, double scale)
{
    //setting SEAL params for context
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
//    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 50,30,30,30,50 }));

    parms.set_coeff_modulus(coeff_modulus);

    seal_struct seal { SEALContext(parms) };
    seal.context_ptr = SEALContext(parms);

    seal.poly_modulus_degree = poly_modulus_degree;
    //seal.bit_sizes = bit_sizes;
    seal.scale= scale;

    seal.evaluator_ptr = make_shared<Evaluator>(seal.context_ptr);
    seal.encoder_ptr = make_shared<CKKSEncoder>(seal.context_ptr);
    seal.keygen_ptr = make_shared<KeyGenerator>(seal.context_ptr);

    seal::PublicKey pk;
    seal.keygen_ptr->create_public_key(pk);
    SecretKey sk  = seal.keygen_ptr->secret_key();
    seal.encryptor_ptr = make_shared<Encryptor>(seal.context_ptr, pk);
    seal.decryptor_ptr = make_shared<Decryptor>(seal.context_ptr, sk);
    seal.pk_ptr = make_shared<seal::PublicKey>(pk);
    seal.sk_ptr = make_shared<SecretKey>(sk);

    RelinKeys relin_keys;
    seal.keygen_ptr->create_relin_keys(relin_keys);
    seal.relink_ptr = make_shared<RelinKeys>(relin_keys);

    return make_shared<seal_struct>(seal);
}
