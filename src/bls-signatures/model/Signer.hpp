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
        // signs the bit table of the BF
        P1& sign(bloom_filter* bf);
        // reconstructs all BFs in the container, then signs all BFs, aggregates the signatures, and return the aggregate signature
        P1 sign(BloomFilterContainer* container);
        // signs the byte array
        P1& sign(byte* message, size_t size);

        void printByte(unsigned char n);
        void printFilter(bloom_filter* m_bloomFilter);
        // aggregates the signed messages via blst::Pairing and aggregates the signatatures, the tries to verify
        static bool verify(std::vector<SignedMessage> messages, std::vector<P1_Affine> signatures);
        // verifies a single message and a public key with a single signature
        static bool verify(byte* message, size_t size, P1_Affine* signature, P2_Affine pk);
        // verifies a group of messages with a signle aggregate signature
        static bool verify(std::vector<SignedMessage> messages, P1_Affine* signature);


        static P1_Affine aggregateSignatures(std::vector<P1_Affine> signatures);

    };
}

#endif