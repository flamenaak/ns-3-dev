/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "ns3/core-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/blst.h"
#include "ns3/bloom_filter.hpp"

#include <stdio.h>
#include <assert.h>
#include <malloc.h>
#include <stdlib.h>

using namespace ns3;
using namespace blst;
using namespace std;

P1_Affine aggregate_signatures(vector<P1_Affine> signatures)
{
    vector<P1_Affine>::iterator it = signatures.begin();
    P1 res;
    for (vector<P1_Affine>::iterator it = signatures.begin(); it < signatures.end(); it++)
    {
        res.aggregate(*it);
    }
    return (res.to_affine());
}

vector<uint8_t> extractByteVector(bloom_filter filter)
{
    return vector<uint8_t>((uint8_t*)filter.table(), (uint8_t*)filter.table() + filter.size());
}

int main(int argc, char* argv[])
{
    static const std::size_t UNIVERSAL_SEED = 10;
    float p = 0.02;
    int n = 200;
    // int m = 15;
    // int k = 3;

    string str1 = "content1";
    string str2 = "content2";
    string str3 = "content3";
    string str4 = "content4";

    //Ptr<MyBloom_filter> myfilter = CreateObject<MyBloom_filter>(IBF_PEC, FPP, ns3::UNIVERSAL_SEED);

    bloom_filter filter1 = bloom_filter(n, p, UNIVERSAL_SEED);
    bloom_filter filter2 = bloom_filter(n, p, UNIVERSAL_SEED);
    bloom_filter filter3 = bloom_filter(n, p, UNIVERSAL_SEED);

    filter1.insert(str1);
    filter2.insert(str2);
    filter3.insert(str3);

    if (filter1.contains(str1)) {
        std::cout << "filter1 contains " << str1 << std::endl;
    }
    else {
        std::cout << "ERROR!!!! filter1 DOES NOT contain " << str1 << std::endl;
    }
    srand(25);
    uint8_t seed[32] = { 0 };

    vector<uint8_t> v1((uint8_t*)filter1.table(), (uint8_t*)filter1.table() + filter1.size());
    uint8_t msg1[v1.size()];
    copy(v1.begin(), v1.end(), msg1);

    bloom_filter bf4 = filter1;

    if (bf4.contains(str1)) {
        std::cout << "bf4 contains " << str1 << std::endl;
    }

    vector<uint8_t> v2((uint8_t*)filter2.table(), (uint8_t*)filter2.table() + filter2.size());
    uint8_t msg2[v2.size()];
    copy(v2.begin(), v2.end(), msg2);

    vector<uint8_t> v3((uint8_t*)filter3.table(), (uint8_t*)filter3.table() + filter3.size());
    uint8_t msg3[v3.size()];
    copy(v3.begin(), v3.end(), msg3);

    SecretKey sk1, sk2, sk3;

    /* Generate key pairs. */
    sk1.keygen(seed, sizeof(seed));
    sk2.keygen(seed, sizeof(seed));
    sk3.keygen(seed, sizeof(seed));
    printf("Got secret keys \n");

    /* Hash messages to points in G1. */
    P1* hash1 = new P1(sk1);
    P1* hash2 = new P1(sk2);
    P1* hash3 = new P1(sk3);

    printf("Initiated hash \n");

    hash1->hash_to(msg1, sizeof(msg1));
    hash2->hash_to(msg2, sizeof(msg2));
    hash3->hash_to(msg3, sizeof(msg3));
    printf("Got hash \n");

    P2* pk1 = (new P2(sk1));
    P2* pk2 = (new P2(sk2));
    P2* pk3 = (new P2(sk3));
    printf("Got public keys \n");

    /** Convert public keys to affine points for verification. */
    P2_Affine* affine_pk1 = new P2_Affine(*pk1);
    P2_Affine* affine_pk2 = new P2_Affine(*pk2);
    P2_Affine* affine_pk3 = new P2_Affine(*pk3);

    /* Compute signatures. */
    P1* sig1 = hash1->sign_with(sk1);
    P1* sig2 = hash2->sign_with(sk2);
    P1* sig3 = hash3->sign_with(sk3);

    /* Convert signatures to affine points for verification. */
    P1_Affine* affine_signature1 = new P1_Affine(*sig1);
    P1_Affine* affine_signature2 = new P1_Affine(*sig2);
    P1_Affine* affine_signature3 = new P1_Affine(*sig3);

    printf("Got affone signatures \n");

    /* If signatures are valid individually these will pass. */
    assert(affine_signature1->core_verify(*affine_pk1, 1, msg1, sizeof(msg1)) == BLST_SUCCESS);
    assert(affine_signature2->core_verify(*affine_pk2, 1, msg2, sizeof(msg2)) == BLST_SUCCESS);
    assert(affine_signature3->core_verify(*affine_pk3, 1, msg3, sizeof(msg3)) == BLST_SUCCESS);

    /* Aggregate signatures in G_1. */
    vector<P1_Affine> list;
    list.push_back(*affine_signature1);
    list.push_back(*affine_signature2);
    list.push_back(*affine_signature3);

    P1_Affine aggregated_signature = aggregate_signatures(list);
    assert(aggregated_signature.in_group() == 1);

    // /* Verify aggregated signatures. */
    Pairing* pairing = new Pairing(1, NULL, 0);
    pairing->aggregate(affine_pk1, NULL, msg1, sizeof(msg1), NULL, 0);
    pairing->aggregate(affine_pk2, NULL, msg2, sizeof(msg2), NULL, 0);
    pairing->aggregate(affine_pk3, NULL, msg3, sizeof(msg3), NULL, 0);

    PT* pt = new PT(aggregated_signature);

    pairing->commit();
    assert(pairing->finalverify(pt) == 1);

    printf("calling Run() \n");

    Simulator::Run();
    Simulator::Destroy();

    printf("done \n");

    return 0;

}
