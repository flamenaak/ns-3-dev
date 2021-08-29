#ifndef BF_CONTAINER_H
#define BF_CONTAINER_H

#include "ns3/blst.h"
#include "types.hpp"
#include "ns3/bloom_filter.hpp"
#include "ns3/BfXorRepresentation.hpp"
#include <memory>

namespace bls_signatures {
    class BloomFilterContainer
    {
    private:
        SignerId m_signerId;
        bloom_filter *m_bloomFilter;
        std::vector<BfXorRepresentation*> m_reductions;
        bool shouldDelete = false;

    public:
        BloomFilterContainer();
        BloomFilterContainer(SignerId signerId);
        BloomFilterContainer(SignerId signerId, int predictedElementCount);
        BloomFilterContainer(SignerId signerId, bloom_filter &bf);
        BloomFilterContainer(SignerId signerId, bloom_filter* bf);
        
        ~BloomFilterContainer();
        SignerId getSignerId();
        void setSignerId(SignerId newId);
        bloom_filter* getBloomFilter();
        void insertIntoBf(std::string text);
        bool bfContains(std::string text);
        std::vector<BfXorRepresentation*> getReductions();

        void addReduction(BfXorRepresentation* reduction);
        /**
         * @brief creates an BfXorRepresentation from the passed BF, adds it to the m_reductions
         * 
         * @param filter 
         * @param sid 
         */
        void addReduction(bloom_filter* filter, SignerId sid);
        /**
         * @brief calculates in how many bits the instance differs from the argument
         * 
         * @param filter 
         * @return unsigned long number of differing bits
         */
        unsigned long calculateDistance(bloom_filter* filter);
        void printFilter();
        unsigned long countSetBits(bloom_filter* filter);
        /**
         * @brief iterates over all BfXorRepresentations in m_reductions, restoring the original BF, returns the restored BFs in a vector 
         * 
         * @return std::vector<BloomFilterContainer*> 
         */
        std::vector<BloomFilterContainer*> reconstructBfs();

        // ------------------ Serialization --------------------------------
        /**
         * @brief Serialize in following order
         *  m_signerId
         *  size of m_reduction
         *  m_reductions
         *  size of m_bloomFilter table
         *  m_bloomFilter.table()
         *  m_bloomFilter.salt_count
         *  m_bloomFilter.element_count
         * @param buffer
         * @param bufferSize
         */
        void serialize(unsigned char* buffer, size_t bufferSize);
        /**
         * @brief populates the object by deserializing the @param data
         * 
         * @param data 
         */
        void deserialize(unsigned char* data);
        size_t getByteSize();
        bool equals(BloomFilterContainer* other);
        /**
         * @brief like equals but does not care about signerId, only about the content
         *
         * @param other
         * @return true
         * @return false
         */
        bool shallowEquals(BloomFilterContainer* other);
        /**
         * @brief If @param other does not have any BfXorRepresentations, it is added as one into the current BfContainer.
         * If @param other has the same bf as current, its BfXorRepresentations are moved into the current and an extra
         * BfXorRepresentation with an empty index array is added
         * @param other
         * @return true if merge was allowed
         * @return false if merge was not allowed
         */
        bool merge(BloomFilterContainer* other);

        blst::P2_Affine getPublicKey(SignerId signerId);

    private:
        unsigned int countSetBitsInChar(unsigned char n);
        void printByte(unsigned char n);

    };
}

#endif