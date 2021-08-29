#include "BfXorRepresentation.hpp"

namespace bls_signatures {
    BfXorRepresentation::BfXorRepresentation(/* args */)
    {
        m_indexVector.clear();
        m_signerId = 0;
    }

    BfXorRepresentation::BfXorRepresentation(SignerId sid, std::vector<BfIndex> indexVector, size_t elementCount)
    {
        m_indexVector = indexVector;
        m_signerId = sid;
        m_elementCount = elementCount;
    }

    BfXorRepresentation::~BfXorRepresentation()
    {    }

    SignerId BfXorRepresentation::getSignerId()
    {
        return m_signerId;
    }

    std::vector<BfIndex> BfXorRepresentation::getIndexVector()
    {
        return m_indexVector;
    }

    size_t BfXorRepresentation::getElementCount()
    {
        return m_elementCount;
    }

    void BfXorRepresentation::printIndexVector()
    {
        printf("printing index vector \n");
        for (std::vector<BfIndex>::iterator it = m_indexVector.begin(); it != m_indexVector.end(); ++it) {
            printf("%lu; ", *it);
        }
        printf("\n");
    }

    size_t BfXorRepresentation::getByteSize()
    {
        return (signerBytes + size_tBytes + size_tBytes + (m_indexVector.size() * bfIndexBytes));
    }

    /**
     * @brief serialize into the buffer in order
     *  1) SignerId
     *  2) Element count
     *  3) Index vector size
     *  4) Index vector
     *
     * !! IMPORTANT : adjust getByteSize() if you change serialization
     *
     * @param buffer
     * @param bufferSize
     */
    void BfXorRepresentation::serialize(unsigned char* buffer, size_t bufferSize)
    {
        unsigned char* charptr;

        std::vector<unsigned char> bufferVct = std::vector<unsigned char>();
        bufferVct.reserve(bufferSize);

        //serialize m_signerId
        charptr = (unsigned char*)&m_signerId;
        for (int i = 0; i < signerBytes; i++) {
            bufferVct.push_back(*(charptr + i));
        }

        // serialize m_elementCount
        charptr = (unsigned char*)&m_elementCount;
        for (int i = 0; i < size_tBytes; i++) {
            bufferVct.push_back(*(charptr + i));
        }

        // serialize size of m_indexVector
        size_t vectorSize = m_indexVector.size();
        charptr = (unsigned char*)&vectorSize;
        for (int i = 0; i < size_tBytes; i++) {
            bufferVct.push_back(*(charptr + i));
        }

        //serialize indexVector
        for (size_t i = 0; i < vectorSize; i++)
        {
            charptr = (unsigned char*)&m_indexVector[i];
            for (int j = 0; j < bfIndexBytes; j++) {
                bufferVct.push_back(*(charptr + j));
            }
        }

        copy(bufferVct.begin(), bufferVct.end(), buffer);
    }

    void BfXorRepresentation::deserialize(unsigned char* data)
    {
        m_signerId = *((SignerId*)data);
        data += signerBytes;

        m_elementCount = *((size_t*)data);
        data += size_tBytes;

        size_t indexVectorSize = *((size_t*)data);
        data += size_tBytes;

        for (size_t i = 0; i < indexVectorSize; i++) {
            m_indexVector.push_back(*((BfIndex*)data));
            data += bfIndexBytes;
        }
    }

    bool BfXorRepresentation::equals(BfXorRepresentation* other)
    {
        if (m_signerId != other->getSignerId()) return false;
        if (m_elementCount != other->getElementCount()) return false;
        if (m_indexVector.size() != other->getIndexVector().size()) return false;
        for (size_t i = 0; i < m_indexVector.size(); i++) {
            if (m_indexVector[i] != other->getIndexVector()[i]) return false;
        }
        return true;
    }

    bool BfXorRepresentation::shallowEquals(BfXorRepresentation* other)
    {
        if (m_elementCount != other->getElementCount()) return false;
        if (m_indexVector.size() != other->getIndexVector().size()) return false;
        for (size_t i = 0; i < m_indexVector.size(); i++) {
            if (m_indexVector[i] != other->getIndexVector()[i]) return false;
        }
        return true;
    }
}