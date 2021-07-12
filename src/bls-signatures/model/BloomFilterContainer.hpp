#ifndef BF_CONTAINER_H
#define BF_CONTAINER_H

#include "ns3/blst.h"
#include "types.hpp"
#include "ns3/myresultapp.h"
#include "ns3/BfXorRepresentation.hpp"
#include <memory>

namespace bls_signatures {
    class BloomFilterContainer
    {
    private:
        SignerId m_signerId;
        bloom_filter m_bloomFilter;
        std::vector<BfXorRepresentation*> m_reductions;
        bool shouldDelete = false;

    public:
        BloomFilterContainer();
        BloomFilterContainer(SignerId signerId);
        BloomFilterContainer(SignerId signerId, bloom_filter bf);
        
        ~BloomFilterContainer();
        SignerId getSignerId();
        bloom_filter getBloomFilter();
        void insertIntoBf(std::string text);
        std::vector<BfXorRepresentation*> getReductions();

        void addReduction(BfXorRepresentation* reduction);
        void addReduction(bloom_filter filter, SignerId sid);
        unsigned long calculateDistance(bloom_filter filter);
        void printFilter();
        unsigned long countSetBits(bloom_filter filter);

        std::vector<BloomFilterContainer> reconstructBfs();

        void serialize(unsigned char* buffer, size_t bufferSize);
        void deserialize(unsigned char* data);
        size_t getByteSize();
        bool equals(BloomFilterContainer* other);
        bool shallowEquals(BloomFilterContainer* other);
        bool merge(BloomFilterContainer* other);

        blst::P2_Affine getPublicKey(SignerId signerId);

    private:
        unsigned int countSetBitsInChar(unsigned char n);
        void printByte(unsigned char n);

    };
}

#endif