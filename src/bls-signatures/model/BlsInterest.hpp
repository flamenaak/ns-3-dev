#include "ns3/blst.h"
#include <string>
#include <stdlib.h>
#include "ns3/BloomFilterContainer.hpp"
#include "ns3/types.hpp"
#include "ns3/Signer.hpp"
#include "ns3/SidPkPair.hpp"

using namespace blst;

namespace bls_signatures
{
    class BlsInterest
    {
    public:
        enum InterestType : char
        {
            CAR,
            CA
        };

    private:
        InterestType m_type;
        std::vector<BloomFilterContainer *> m_bloomFilters;
        P1_Affine *m_signature;
        std::vector<SidPkPair *> m_signerList;

    public:
        BlsInterest();
        BlsInterest(InterestType type, P1_Affine *signature);
        ~BlsInterest();
        std::string _getTypeString();
        InterestType _getInterestType() { return m_type; };
        std::vector<BloomFilterContainer *> _getBloomFilters();
        std::vector<SidPkPair *> _getSignerList();
        void _addSigner(SidPkPair *signerPair);
        P1_Affine *_getSignature();

        void _merge(BlsInterest *other);
        void _merge(BlsInterest *other, vector<SidPkPair *> additionalSignerList);
        void _mergeBf(BloomFilterContainer *bloomFilter);
        void _addBloomFilter(BloomFilterContainer *bf);
        bool _verify();
        size_t _getPublicKeyIndex(SignerId signerId);
    };

    BlsInterest::BlsInterest()
    {
        m_type = CAR;
        m_bloomFilters.clear();
        m_signerList.clear();
    }

    BlsInterest::BlsInterest(InterestType type, P1_Affine *signature)
    {
        m_type = type;
        m_signature = signature;
        m_bloomFilters.clear();
        m_signerList.clear();
    }

    BlsInterest::~BlsInterest()
    {
        m_bloomFilters.~vector();
        m_signerList.~vector();
    }

    std::string BlsInterest::_getTypeString()
    {
        switch (m_type)
        {
        case BlsInterest::CAR:
            return "CAR";
        case BlsInterest::CA:
            return "CA";
        default:
            break;
        }
        return "";
    }

    std::vector<BloomFilterContainer *> BlsInterest::_getBloomFilters()
    {
        return m_bloomFilters;
    }

    P1_Affine *BlsInterest::_getSignature()
    {
        return m_signature;
    }

    void BlsInterest::_addBloomFilter(BloomFilterContainer *bf)
    {
        m_bloomFilters.push_back(bf);
    }

    std::vector<SidPkPair *> BlsInterest::_getSignerList()
    {
        return m_signerList;
    }

    /**
     * @brief adds a new SidPkPair into the signer list avoiding adding duplicates based on SignerId
     * 
     * @param signerPair 
     */
    void BlsInterest::_addSigner(SidPkPair *signerPair)
    {
        for (size_t i = 0; i < m_signerList.size(); i++)
        {
            if (signerPair->m_signerId == m_signerList[i]->m_signerId)
                return;
        }
        m_signerList.push_back(signerPair);
    }

    void BlsInterest::_mergeBf(BloomFilterContainer *bloomFilter)
    {
        // find the closest bloomFilter
        unsigned long minDistance = -1;
        BloomFilterContainer *closestBloomFilter;
        size_t index = 0;
        for (size_t i = 0; i < m_bloomFilters.size(); i++)
        {
            unsigned long distance = m_bloomFilters[i]->calculateDistance(bloomFilter->getBloomFilter());
            if (minDistance == (unsigned long)-1 || distance < minDistance)
            {
                minDistance = distance;
                closestBloomFilter = m_bloomFilters[i];
                index = i;
            }
        }
        if (minDistance <= (unsigned long)DELTA_MAX)
        {
            if (closestBloomFilter->merge(bloomFilter))
            {
                return;
            }
            else if (bloomFilter->merge(closestBloomFilter))
            {
                m_bloomFilters[index] = bloomFilter;
            }
            else
            {
                m_bloomFilters.push_back(bloomFilter);
            }
        }
        else
        {
            // this could be added after this for loop to not slow down next iteration
            printf("Could not reduce bf, the distance is too great: %lu \n", minDistance);
            m_bloomFilters.push_back(bloomFilter);
        }
    }

    void BlsInterest::_merge(BlsInterest *other)
    {
        vector<SidPkPair *> additionalSignerList;
        additionalSignerList.clear();
        return _merge(other, additionalSignerList);
    }

    void BlsInterest::_merge(BlsInterest *other, vector<SidPkPair *> additionalSignerList)
    {
        if (m_type != other->_getInterestType())
        {
            printf("not merging, wrong type \n");
            return;
        }

        if (other->_getBloomFilters().size() == 0)
        {
            printf("not merging, no bloom filters \n");
            return;
        }

        // this is probably not necessary, received interests are already verified

        // if (!other->verify(additionalSignerList)) {
        //   printf("could not verify Interest being merged \n");
        //   return;
        // }

        for (size_t i = 0; i < other->_getBloomFilters().size(); i++)
        {
            _mergeBf(other->_getBloomFilters()[i]);
        }
        // merge the signer lists
        for (size_t i = 0; i < other->_getSignerList().size(); i++)
        {
            m_signerList.push_back(other->_getSignerList()[i]);
        }

        P1 temp = P1(*m_signature);
        temp.aggregate(*other->_getSignature());
        m_signature = new P1_Affine(temp);
    }

    bool BlsInterest::_verify()
    {
        std::vector<SignedMessage> messages;
        messages.clear();

        std::vector<P1_Affine> signatures;
        signatures.clear();
        signatures.push_back(*m_signature);
        BloomFilterContainer *bfContainer;
        BloomFilterContainer *reduction;

        for (size_t i = 0; i < m_bloomFilters.size(); i++)
        {
            bfContainer = m_bloomFilters[i];
            size_t index = _getPublicKeyIndex(bfContainer->getSignerId());

            if (index == (size_t)-1)
            {
                printf("did not find public key of a main container, id: %lu \n", bfContainer->getSignerId());
                return false;
            }
            messages.push_back(SignedMessage(bfContainer->getBloomFilter(), m_signerList[index]->m_pk));

            std::vector<BloomFilterContainer *> reconstructed = bfContainer->reconstructBfs();
            for (size_t j = 0; j < reconstructed.size(); j++)
            {
                reduction = reconstructed[j];
                size_t reductionIndex = _getPublicKeyIndex(reduction->getSignerId());
                if (reductionIndex == (size_t)-1)
                {
                    printf("did not find public key of a reduction \n");
                    return false;
                }
                messages.push_back(SignedMessage(reduction->getBloomFilter(), m_signerList[reductionIndex]->m_pk));
            }
        }
        return Signer::verify(messages, signatures);
    }

    size_t BlsInterest::_getPublicKeyIndex(SignerId signerId)
    {
        for (size_t i = 0; i < m_signerList.size(); i++)
        {
            //printf("index %lu, signer id %lu \n", i, m_signerList[i]->m_signerId);
            if (m_signerList[i]->m_signerId == signerId)
                return i;
        }
        return -1;
    }
}