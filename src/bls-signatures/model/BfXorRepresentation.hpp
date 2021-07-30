#ifndef BF_REDUCTION_H
#define BF_REDUCTION_H

#include "ns3/blst.h"
#include "types.hpp"

namespace bls_signatures {
    
    class BfXorRepresentation
    {
    private:
        SignerId m_signerId;
        std::vector<BfIndex> m_indexVector;
        unsigned long m_elementCount;
    public:
        BfXorRepresentation(/* args */);
        BfXorRepresentation(SignerId sid, std::vector<BfIndex> indexVector, size_t elementCount);
        ~BfXorRepresentation();
        SignerId getSignerId();
        std::vector<BfIndex> getIndexVector();
        size_t getElementCount();
        void printIndexVector();
        void serialize(unsigned char* buffer, size_t bufferSize);
        void deserialize(unsigned char* data);
        size_t getByteSize();

        bool equals(BfXorRepresentation *other);
        bool shallowEquals(BfXorRepresentation *other);
    };
}

#endif