#ifndef TYPES_H
#define TYPES_H

#include "ns3/myresultapp.h"
#include <math.h>

namespace bls_signatures {
    typedef long SignerId;
    typedef long BfIndex;

    const int signerBytes = sizeof(SignerId) / sizeof(unsigned char);
    const int size_tBytes = sizeof(size_t) / sizeof(unsigned char);
    const int bfIndexBytes = sizeof(BfIndex) / sizeof(unsigned char);

    // Bloom filter parameters
    const double BF_P = 0.01;
    const int BF_N = 5;
    const int BF_M = ceil(-((BF_N * log(BF_P)) / pow(log(2), 2))/8)*8;

    // Maximum distance of two BFs that allows efficient XorRepresentation
    const int DELTA_MAX = log2(BF_M);

    const size_t BF_SEED = ns3::UNIVERSAL_SEED;

    const size_t PK_SIZE = 192;
}

#endif