#include "SidPkPair.hpp"

namespace bls_signatures {
    SidPkPair::SidPkPair()
    {
        m_pk = nullptr;
        m_signerId = 0;
    }

    SidPkPair::SidPkPair(SignerId signerId, P2_Affine* pk)
    {
        m_pk = pk;
        m_signerId = signerId;
    }

    SidPkPair::~SidPkPair()
    {
    
    }

    void SidPkPair::serialize(byte* buffer, size_t bufferSize)
    {
        std::vector<unsigned char> bufferVct = std::vector<unsigned char>();
        bufferVct.reserve(bufferSize);
        unsigned char* charptr;
        //serialize m_signerId
        charptr = (unsigned char*)&m_signerId;
        for (int i = 0; i < signerBytes; i++) {
            bufferVct.push_back(*(charptr + i));
        }

        // serialize length of m_pk in bytes
        charptr = (unsigned char*)&PK_SIZE;
        for (int i = 0; i < signerBytes; i++) {
            bufferVct.push_back(*(charptr + i));
        }

        // serialize public key
        // public keys are of length 192
        byte pk[PK_SIZE];
        m_pk->serialize(pk);
        for (size_t i = 0; i < sizeof(pk); i++) {
            bufferVct.push_back(pk[i]);
        }

        copy(bufferVct.begin(), bufferVct.end(), buffer);
    }

    void SidPkPair::deserialize(byte* data)
    {
        m_signerId = *((SignerId*)data);
        data += signerBytes;

        size_t pkSize = *((size_t*)data);
        data += size_tBytes;

        std::vector<byte> bufferVct = std::vector<byte>();
        bufferVct.reserve(pkSize);

        for (size_t i = 0; i < pkSize; i++) {
            bufferVct.push_back(*data);
            data++;
        }

        m_pk = new P2_Affine(bufferVct.data());
    }

    size_t SidPkPair::getByteSize()
    {
        return signerBytes + size_tBytes + PK_SIZE;
    }

    bool SidPkPair::equals(SidPkPair *other)
    {
        if (m_signerId != other->m_signerId) return false;
        return m_pk->is_equal(*(other->m_pk));
    }
};