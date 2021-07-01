#ifndef BF_CONTAINER_H
#define BF_CONTAINER_H

#include "ns3/blst.h"
#include "types.hpp"
#include "ns3/myresultapp.h"
#include "ns3/BloomFilterReduction.hpp"

namespace bls_signatures {
    class BloomFilterContainer
    {
    private:
        SignerId m_signerId;
        bloom_filter* m_bloomFilter;
        std::vector<BloomFilterReduction*> m_reductions;

    public:
        BloomFilterContainer(SignerId signerId, bloom_filter* bf);
        ~BloomFilterContainer();
        SignerId getSignerId();
        bloom_filter* getBloomFilter();
        std::vector<BloomFilterReduction*> getReductions();

        void addReduction(BloomFilterReduction* reduction);
        void addReduction(bloom_filter* filter, SignerId sid);
        unsigned long calculateDistance(bloom_filter* filter);
        void printFilter();
        unsigned long countSetBits(bloom_filter* filter);

    private:
        unsigned int countSetBitsInChar(unsigned char n);
        void printByte(unsigned char n);

    };

    BloomFilterContainer::BloomFilterContainer(SignerId signerId, bloom_filter* bf)
    {
        m_bloomFilter = bf;
        m_signerId = signerId;
        m_reductions.clear();
    }

    BloomFilterContainer::~BloomFilterContainer()
    {
        m_reductions.clear();
        m_bloomFilter->clear();
    }

    SignerId BloomFilterContainer::getSignerId()
    {
        return m_signerId;
    }

    bloom_filter* BloomFilterContainer::getBloomFilter()
    {
        return m_bloomFilter;
    }

    std::vector<BloomFilterReduction*> BloomFilterContainer::getReductions()
    {
        return m_reductions;
    }

    void BloomFilterContainer::addReduction(BloomFilterReduction* reductionPtr)
    {
        m_reductions.push_back(reductionPtr);
    }

    void BloomFilterContainer::addReduction(bloom_filter* filter, SignerId sid)
    {
        bloom_filter* xorFilter = new bloom_filter(m_bloomFilter->predicted_element_count_,
            m_bloomFilter->desired_false_positive_probability_,
            m_bloomFilter->random_seed_);
        *xorFilter = *m_bloomFilter ^= *filter;

        std::vector<BfIndex> indexVector = *(new std::vector<BfIndex>());
        for (size_t i = 0; i < xorFilter->size();i++) {
            blst::byte n = xorFilter->table()[i];
            blst::byte j = 0;
            while (j < 8) {
                if ((n & 1) == 1) {
                    indexVector.push_back(i * sizeof(blst::byte) + j);
                }
                n >>= 1;
                j++;
            }
        }
        BloomFilterReduction* reduction = new BloomFilterReduction(sid, indexVector);
        m_reductions.push_back(reduction);

        delete xorFilter;
    }

    unsigned long BloomFilterContainer::calculateDistance(bloom_filter* filter)
    {
        bloom_filter* xorFilter = new bloom_filter(m_bloomFilter->predicted_element_count_,
            m_bloomFilter->desired_false_positive_probability_,
            m_bloomFilter->random_seed_);
        *xorFilter = *m_bloomFilter ^= *filter;
        unsigned long count = countSetBits(xorFilter);
        delete xorFilter;
        return count;
    }

    void BloomFilterContainer::printByte(unsigned char n)
    {
        blst::byte i = 0;
        while (i < 8) {
            printf("%i", n & 1);
            n >>= 1;
            i++;
        }
    }

    void BloomFilterContainer::printFilter()
    {
        for (unsigned long i = 0; i < m_bloomFilter->size(); i++) {
            //printf("%i", filter->table()[i]);
            printByte(m_bloomFilter->table()[i]);
        }
        printf("\n");
    }

    unsigned int BloomFilterContainer::countSetBitsInChar(unsigned char n)
    {
        unsigned char count = 0;
        while (n) {
            count += n & 1;
            n >>= 1;
        }
        return count;
    }

    unsigned long BloomFilterContainer::countSetBits(bloom_filter* filter)
    {
        unsigned long count = 0;
        for (unsigned long i = 0; i < filter->size(); i++) {
            count += countSetBitsInChar(filter->table()[i]);
        }
        return count;
    }
}

#endif