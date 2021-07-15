#include "BloomFilterContainer.hpp"
#include <cmath>

namespace bls_signatures {
    BloomFilterContainer::BloomFilterContainer()
    {
        m_bloomFilter = new bloom_filter(BF_N, BF_P, BF_SEED);
        m_bloomFilter->clear();
        m_signerId = 0;
        m_reductions.clear();
        shouldDelete = true;
    }

    BloomFilterContainer::BloomFilterContainer(SignerId signerId)
    {
        m_bloomFilter = new bloom_filter(BF_N, BF_P, BF_SEED);
        m_bloomFilter->clear();
        m_signerId = signerId;
        m_reductions.clear();
        shouldDelete = true;
    }

    BloomFilterContainer::BloomFilterContainer(SignerId signerId, bloom_filter& bf)
    {
        m_bloomFilter = &bf;
        m_signerId = signerId;
        m_reductions.clear();
    }

    BloomFilterContainer::~BloomFilterContainer()
    {
        m_reductions.clear();
        m_bloomFilter->clear();
        if (shouldDelete) {
            delete m_bloomFilter;
        }
        else {
            m_bloomFilter = nullptr;
        }
    }

    SignerId BloomFilterContainer::getSignerId()
    {
        return m_signerId;
    }

    bloom_filter* BloomFilterContainer::getBloomFilter()
    {
        return m_bloomFilter;
    }

    void BloomFilterContainer::insertIntoBf(std::string text)
    {
        m_bloomFilter->insert(text);
    }

    std::vector<BfXorRepresentation*> BloomFilterContainer::getReductions()
    {
        return m_reductions;
    }

    void BloomFilterContainer::addReduction(BfXorRepresentation* reductionPtr)
    {
        m_reductions.push_back(reductionPtr);
    }

    void BloomFilterContainer::addReduction(bloom_filter* filter, SignerId sid)
    {
        bloom_filter* xorFilter = new bloom_filter(m_bloomFilter->predicted_element_count_,
            m_bloomFilter->desired_false_positive_probability_,
            m_bloomFilter->random_seed_);
        xorFilter->set_salt_count(m_bloomFilter->salt_count());
        xorFilter->assign_bitTable((unsigned char*)filter->table(), filter->size());
        *xorFilter ^= *m_bloomFilter;

        std::vector<BfIndex> indexVector = *(new std::vector<BfIndex>());
        for (size_t i = 0; i < xorFilter->size() / 8;i++) {
            blst::byte n = xorFilter->table()[i];
            blst::byte j = 0;
            while (j < 8) {
                if ((n & 1) == 1) {
                    indexVector.push_back((BfIndex)(i * 8) + j);
                }
                n >>= 1;
                j++;
            }
        }
        BfXorRepresentation* reduction = new BfXorRepresentation(sid, indexVector, filter->element_count());
        m_reductions.push_back(reduction);

        delete xorFilter;
    }

    unsigned long BloomFilterContainer::calculateDistance(bloom_filter* filter)
    {
        bloom_filter* xorFilter = new bloom_filter(m_bloomFilter->element_count(),
            m_bloomFilter->desired_false_positive_probability_,
            m_bloomFilter->random_seed_);
        xorFilter->set_salt_count(m_bloomFilter->salt_count());
        xorFilter->assign_bitTable((unsigned char*)filter->table(), filter->size());
        *xorFilter ^= *m_bloomFilter;

        unsigned long count = countSetBits(xorFilter);
        delete xorFilter;
        return count;
    }

    std::vector<BloomFilterContainer*> BloomFilterContainer::reconstructBfs()
    {
        std::vector<BloomFilterContainer*> buffer;
        for (size_t i = 0; i < m_reductions.size(); i++)
        {
            BfXorRepresentation* reduction = m_reductions[i];
            bloom_filter* bf = new bloom_filter(BF_N, BF_P, BF_SEED);
            *bf = *m_bloomFilter;
            bf->set_inserted_element_count(reduction->getElementCount());
            for (size_t j = 0; j < reduction->getIndexVector().size(); j++)
            {
                BfIndex index = reduction->getIndexVector()[j];
                size_t byteIndex = index / 8;
                size_t bitIndex = index % 8;

                bf->bit_table_[byteIndex] ^= (1 << bitIndex);
            }
            BloomFilterContainer* container = new BloomFilterContainer(reduction->getSignerId(), *bf);
            buffer.push_back(container);
        }
        return buffer;
    }

    bool BloomFilterContainer::equals(BloomFilterContainer* other)
    {
        if (m_signerId != other->getSignerId()) return false;
        if (!(*m_bloomFilter == *(other->getBloomFilter()))) return false;
        if (m_reductions.size() != other->getReductions().size()) return false;

        for (size_t i = 0; i < m_reductions.size(); i++) {
            if (!m_reductions[i]->equals(other->getReductions()[i])) return false;
        }
        return true;
    }

    /**
     * @brief like equals but does not care about signerId, only about the content
     *
     * @param other
     * @return true
     * @return false
     */
    bool BloomFilterContainer::shallowEquals(BloomFilterContainer* other)
    {
        if (!(*m_bloomFilter == *(other->getBloomFilter()))) return false;
        if (m_reductions.size() != other->getReductions().size()) return false;

        for (size_t i = 0; i < m_reductions.size(); i++) {
            if (!m_reductions[i]->shallowEquals(other->getReductions()[i])) return false;
        }
        return true;
    }

    /**
     * @brief If @param other does not have any BfXorRepresentations, it is added as one into the current BfContainer.
     * If @param other has the same bf as current, its BfXorRepresentations are moved into the current and an extra
     * BfXorRepresentation with an empty index array is added
     * @param other
     * @return true if merge was allowed
     * @return false if merge was not allowed
     */
    bool BloomFilterContainer::merge(BloomFilterContainer* other)
    {
        if (*other->getBloomFilter() == *m_bloomFilter) {
            for (size_t i = 0; i < other->getReductions().size(); i++) {
                m_reductions.push_back(other->getReductions()[i]);
            }
        }
        else if (other->getReductions().size() > 0) {
            return false;
        }
        addReduction(other->getBloomFilter(), other->getSignerId());

        return true;
    }

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
    void BloomFilterContainer::serialize(unsigned char* buffer, size_t bufferSize)
    {
        unsigned char* charptr;

        std::vector<unsigned char> bufferVct = std::vector<unsigned char>();
        bufferVct.reserve(bufferSize);

        //serialize m_signerId
        charptr = (unsigned char*)&m_signerId;
        for (int i = 0; i < signerBytes; i++) {
            bufferVct.push_back(*(charptr + i));
        }
        // serialize size of m_reductions
        size_t vectorSize = m_reductions.size();
        charptr = (unsigned char*)&vectorSize;
        for (int i = 0; i < size_tBytes; i++) {
            bufferVct.push_back(*(charptr + i));
        }

        //serialize reductions
        for (size_t i = 0; i < vectorSize; i++) {
            BfXorRepresentation* reduction = m_reductions[i];
            unsigned char reductionBuffer[reduction->getByteSize()];
            reduction->serialize(reductionBuffer, reduction->getByteSize());
            for (size_t j = 0; j < reduction->getByteSize(); j++) {
                bufferVct.push_back(*(reductionBuffer + j));
            }
        }

        // serialize size of m_bloomFilter.table() in bytes
        size_t filterSize = m_bloomFilter->size() / 8;
        charptr = (unsigned char*)&filterSize;
        for (int i = 0; i < size_tBytes; i++) {
            bufferVct.push_back(*(charptr + i));
        }

        // serialize bit table of m_bloomFilter
        for (size_t i = 0; i < m_bloomFilter->size() / 8; i++) {
            bufferVct.push_back(m_bloomFilter->table()[i]);
        }

        // serialize salt_count
        size_t filteSaltCount = m_bloomFilter->salt_count();
        charptr = (unsigned char*)&filteSaltCount;
        for (int i = 0; i < size_tBytes; i++) {
            bufferVct.push_back(*(charptr + i));
        }
        // serialize element_count
        size_t elementCount = m_bloomFilter->element_count();
        charptr = (unsigned char*)&elementCount;
        for (int i = 0; i < size_tBytes; i++) {
            bufferVct.push_back(*(charptr + i));
        }

        copy(bufferVct.begin(), bufferVct.end(), buffer);
    }

    void BloomFilterContainer::deserialize(unsigned char* data)
    {
        //deserialize signerId
        m_signerId = *((SignerId*)data);
        data += signerBytes;
        //deserialize reduction count
        size_t reductionVectorSize = *((size_t*)data);
        data += size_tBytes;
        //deserialize reduction vector
        for (size_t i = 0; i < reductionVectorSize; i++) {
            BfXorRepresentation* reduction = new BfXorRepresentation();
            reduction->deserialize(data);
            m_reductions.push_back(reduction);
            data += reduction->getByteSize();
        }
        //deserialize bit table size
        size_t bfBitTableSize = *((size_t*)data);
        data += size_tBytes;

        //deserialize bit table
        for (size_t i = 0; i < bfBitTableSize; i++) {
            m_bloomFilter->bit_table_[i] = *(data);
            data++;
        }

        //deserialize salt count
        size_t bfSaltCount = *((size_t*)data);
        m_bloomFilter->set_salt_count(bfSaltCount);
        data += size_tBytes;

        //deserialize element count
        size_t bfElementCount = *((size_t*)data);
        m_bloomFilter->set_inserted_element_count(bfElementCount);
        data += size_tBytes;
    }

    size_t BloomFilterContainer::getByteSize()
    {
        size_t reductionSize = 0;
        for (size_t i = 0; i < m_reductions.size(); i++) {
            reductionSize += m_reductions[i]->getByteSize();
        }

        return (signerBytes + size_tBytes + reductionSize + size_tBytes + m_bloomFilter->size() / 8 + size_tBytes + size_tBytes);
    }

    // ------------------ Misc --------------------------------
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
        for (unsigned long i = 0; i < m_bloomFilter->size() / 8; i++) {
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
        for (unsigned long i = 0; i < filter->size() / 8; i++) {
            count += countSetBitsInChar(filter->table()[i]);
        }
        return count;
    }
}