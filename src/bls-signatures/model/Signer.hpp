#ifndef SIGNER_H
#define SIGNER_H

#include "ns3/blst.h"
#include "ns3/bloom_filter.hpp"
#include "ns3/BloomFilterContainer.hpp"
#include "ns3/SignedMessage.hpp"
#include <stdio.h>

using namespace blst;

namespace bls_signatures {
    class Signer
    {
    private:
        bloom_filter* m_bf;
        SecretKey* m_sk;
        P2_Affine* m_pk;
    public:
        Signer(/* args */);
        Signer(byte seed[32], size_t size);
        ~Signer();

        P2_Affine* getPublicKey();

        P1& sign(bloom_filter* bf);
        P1 sign(BloomFilterContainer* container);
        P1& sign(byte* message, size_t size);

        void printByte(unsigned char n);
        void printFilter(bloom_filter* m_bloomFilter);

        static bool verify(std::vector<SignedMessage> messages, std::vector<P1_Affine> signatures);
        static bool verify(byte* message, size_t size, P1_Affine* signature, P2_Affine pk);
        static bool verify(std::vector<SignedMessage> messages, P1_Affine* signature);


        static P1_Affine aggregateSignatures(std::vector<P1_Affine> signatures);

    };
}

#endif