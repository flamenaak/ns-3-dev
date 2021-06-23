#include <stdio.h>
#include <assert.h>
#include <malloc.h>
#include <stdlib.h>
#include "./helper.cpp"

using namespace blst;

int main(int argc, char *argv[])
{
    srand(25);
    uint8_t seed[32] = {0};

    uint8_t msg1[8] = {1, 1, 0, 0, 0, 0, 0, 0};
    uint8_t msg2[8] = {0, 0, 0, 1, 0, 1, 0, 0};
    uint8_t msg3[8] = {0, 0, 0, 0, 0, 0, 1, 1};

    SecretKey sk1, sk2, sk3;

    /* Generate key pairs. */
    sk1.keygen(seed, sizeof(seed));
    sk2.keygen(seed, sizeof(seed));
    sk3.keygen(seed, sizeof(seed));
    printf("Got secret keys \n");

    /* Hash messages to points in G1. */
    P1 *hash1 = new P1(sk1);
    P1 *hash2 = new P1(sk2);
    P1 *hash3 = new P1(sk3);

    printf("Initiated hash \n");
    
    hash1->hash_to(msg1, sizeof(msg1));
    hash2->hash_to(msg2, sizeof(msg2));
    hash3->hash_to(msg3, sizeof(msg3));
    printf("Got hash \n");

    P2 *pk1 = (new P2(sk1));
    P2 *pk2 = (new P2(sk2));
    P2 *pk3 = (new P2(sk3));
    printf("Got public keys \n");

    /** Convert public keys to affine points for verification. */
    P2_Affine *affine_pk1 = new P2_Affine(*pk1);
    P2_Affine *affine_pk2 = new P2_Affine(*pk2);
    P2_Affine *affine_pk3 = new P2_Affine(*pk3);

    /* Compute signatures. */
    P1 *sig1 = hash1->sign_with(sk1);
    P1 *sig2 = hash2->sign_with(sk2);
    P1 *sig3 = hash3->sign_with(sk3);

    /* Convert signatures to affine points for verification. */
    P1_Affine *affine_signature1 = new P1_Affine(*sig1);
    P1_Affine *affine_signature2 = new P1_Affine(*sig2);
    P1_Affine *affine_signature3 = new P1_Affine(*sig3);

    printf("Got affone signatures \n");

    /* If signatures are valid individually these will pass. */
    assert(affine_signature1->core_verify(*affine_pk1, 1, msg1, sizeof(msg1)) == BLST_SUCCESS);
    assert(affine_signature2->core_verify(*affine_pk2, 1, msg2, sizeof(msg2)) == BLST_SUCCESS);
    assert(affine_signature3->core_verify(*affine_pk3, 1, msg3, sizeof(msg3)) == BLST_SUCCESS);

    /* Aggregate signatures in G_1. */
    P1_Affine *myP1s[] = {affine_signature1, affine_signature2, affine_signature3};

    vector<P1_Affine> list;
    list.push_back(*affine_signature1);
    list.push_back(*affine_signature2);
    list.push_back(*affine_signature3);

    P1_Affine aggregated_signature = bls_helper::aggregate_signatures(list);
    assert(aggregated_signature.in_group() == 1);

    // /* Verify aggregated signatures. */
    Pairing *pairing = new Pairing(1, NULL, 0);
    pairing->aggregate(affine_pk1, NULL , msg1, sizeof(msg1), NULL, 0);
    pairing->aggregate(affine_pk2, NULL , msg2, sizeof(msg2), NULL, 0);
    pairing->aggregate(affine_pk3, NULL , msg3, sizeof(msg3), NULL, 0);

    PT* pt = new PT(aggregated_signature);

    pairing->commit();
    assert(pairing->finalverify(pt) == 1);

    printf("done \n");
}
