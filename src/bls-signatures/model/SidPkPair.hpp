#ifndef SidPkPair_H
#define SidPkPair_H


#include "ns3/blst.h"
#include "types.hpp"

using namespace blst;

namespace bls_signatures {
    class SidPkPair
    {
    public:
        P2_Affine *m_pk;
        SignerId m_signerId;
    public:
        SidPkPair();
        SidPkPair(SignerId signerId, P2_Affine& pk);
        ~SidPkPair();

        void serialize(byte* buffer, size_t bufferSize);
        void deserialize(byte* data);
        size_t getByteSize();
        bool equals(SidPkPair *other);
    };    
};

#endif