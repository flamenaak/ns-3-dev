#ifndef BF_REDUCTION_H
#define BF_REDUCTION_H

#include "ns3/blst.h"
#include "types.hpp"

namespace bls_signatures
{

    class BfXorRepresentation
    {
    private:
        SignerId m_signerId;
        // indices of the XOR
        std::vector<BfIndex> m_indexVector;
        // stores inserted element count of the original BF
        unsigned long m_elementCount;

    public:
        BfXorRepresentation(/* args */);
        BfXorRepresentation(SignerId sid, std::vector<BfIndex> indexVector, size_t elementCount);
        ~BfXorRepresentation();
        SignerId getSignerId();
        std::vector<BfIndex> getIndexVector();
        size_t getElementCount();
        void printIndexVector();
        void serialize(unsigned char *buffer, size_t bufferSize);
        void deserialize(unsigned char *data);
        size_t getByteSize();
        /**
         * @brief compares value of all member variables with @param other
         * 
         * @param other 
         * @return true if all values match
         * @return false if they don't
         */
        bool equals(BfXorRepresentation *other);
        /**
         * @brief like equals but does not care about id's only the data
         *
         * @param other
         * @return true
         * @return false
         */
        bool shallowEquals(BfXorRepresentation *other);
    };
}

#endif