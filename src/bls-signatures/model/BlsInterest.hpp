#include "ns3/blst.hpp"
#include <string>
#include <stdlib.h>
#include "ns3/BloomFilterContainer.hpp"
#include "ns3/types.hpp"
#include "ns3/Signer.hpp"
#include "ns3/SidPkPair.hpp"

using namespace blst;

namespace bls_signatures {
    class BlsInterest
    {
    public:
        enum InterestType : char {
            CAR, CA
        };

    private:
        InterestType m_type;
        std::vector<BloomFilterContainer*> m_bloomFilters;
        P1_Affine* m_signature;
        std::vector<SidPkPair*> m_signerList;

    public:
        BlsInterest();
        BlsInterest(InterestType type, P1_Affine* signature);
        ~BlsInterest();
        std::string getTypeString();
        InterestType getType() { return m_type; };
        std::vector<BloomFilterContainer*> getBloomFilters();
        std::vector<SidPkPair*> getSignerList();
        void addSigner(SidPkPair* signerPair);
        P1_Affine* getSignature();

        void merge(BlsInterest* other);
        void addBloomFilter(BloomFilterContainer* bf);
        bool verify();
        size_t getPublicKeyIndex(SignerId signerId);
    };

    BlsInterest::BlsInterest()
    {
        m_type = CAR;
        m_bloomFilters.clear();
        m_signerList.clear();
    }

    BlsInterest::BlsInterest(InterestType type, P1_Affine* signature)
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

    std::string BlsInterest::getTypeString()
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

    std::vector<BloomFilterContainer*> BlsInterest::getBloomFilters()
    {
        return m_bloomFilters;
    }

    P1_Affine* BlsInterest::getSignature()
    {
        return m_signature;
    }

    void BlsInterest::addBloomFilter(BloomFilterContainer* bf)
    {
        m_bloomFilters.push_back(bf);
    }

    std::vector<SidPkPair*> BlsInterest::getSignerList()
    {
        return m_signerList;
    }

    /**
     * @brief adds a new SidPkPair into the signer list avoiding adding duplicates based on SignerId
     * 
     * @param signerPair 
     */
    void BlsInterest::addSigner(SidPkPair* signerPair)
    {
        for (size_t i = 0; i < m_signerList.size(); i++) {
            if (signerPair->m_signerId == m_signerList[i]->m_signerId) return;
        }
        m_signerList.push_back(signerPair);
    }

    void BlsInterest::merge(BlsInterest* other)
    {
        if (m_type != other->getType()) {
            printf("not merging, wrong type \n");
            return;
        }

        if (other->getBloomFilters().size() == 0) {
            printf("not merging, no bloom filters \n");
            return;
        }

        if (!other->verify()) {
            printf("could not verify BlsInterest being merged \n");
            return;
        }

        for (size_t i = 0; i < other->getBloomFilters().size(); i++) {
            BloomFilterContainer* bloomFilter = other->getBloomFilters()[i];

            // find the closest bloomFilter
            unsigned long minDistance = -1;
            BloomFilterContainer* closestBloomFilter;
            for (size_t j = 0; j < m_bloomFilters.size(); j++) {
                unsigned long distance = m_bloomFilters[j]->calculateDistance(bloomFilter->getBloomFilter());
                if (minDistance == (unsigned long)-1 || distance < minDistance) {
                    minDistance = distance;
                    closestBloomFilter = m_bloomFilters[j];
                }
            }

            if (minDistance <= (unsigned long)DELTA_MAX) {
                if (closestBloomFilter->merge(bloomFilter)) {
                    continue;
                }
                else if (bloomFilter->merge(closestBloomFilter)) {
                    m_bloomFilters[i] = bloomFilter;
                }
                else {
                    m_bloomFilters.push_back(bloomFilter);
                }
            }
            else {
                // this could be added after this for loop to not slow down next iteration
                printf("Could not reduce bf, the distance is too great: %lu \n", minDistance);
                m_bloomFilters.push_back(bloomFilter);
            }
        }
        // merge the signer lists
        for (size_t i = 0; i < other->getSignerList().size(); i++) {
            m_signerList.push_back(other->getSignerList()[i]);
        }

        P1 temp = P1(*m_signature);
        temp.aggregate(*other->getSignature());
        m_signature = new P1_Affine(temp);
    }

    bool BlsInterest::verify()
    {
        std::vector<SignedMessage> messages;
        messages.clear();

        std::vector<P1_Affine> signatures;
        signatures.clear();
        signatures.push_back(*m_signature);
        BloomFilterContainer* bfContainer;
        BloomFilterContainer* reduction;
        
        for (size_t i = 0; i < m_bloomFilters.size(); i++) {
            bfContainer = m_bloomFilters[i];
            size_t index = getPublicKeyIndex(bfContainer->getSignerId());

            if (index == (size_t)-1) {
                printf("did not find public key of a main container, id: %lu \n", bfContainer->getSignerId());
                return false;
            }
            messages.push_back(SignedMessage(bfContainer->getBloomFilter(), m_signerList[index]->m_pk));

            std::vector<BloomFilterContainer*> reconstructed = bfContainer->reconstructBfs();
            for (size_t j = 0; j < reconstructed.size(); j++) {
                reduction = reconstructed[j];
                size_t reductionIndex = getPublicKeyIndex(reduction->getSignerId());
                if (reductionIndex == (size_t)-1) {
                    printf("did not find public key of a reduction \n");
                    return false;
                }
                messages.push_back(SignedMessage(reduction->getBloomFilter(), m_signerList[reductionIndex]->m_pk));
            }
        }
        return Signer::verify(messages, signatures);
    }

    size_t BlsInterest::getPublicKeyIndex(SignerId signerId)
    {
        for (size_t i = 0; i < m_signerList.size(); i++) {
            //printf("index %lu, signer id %lu \n", i, m_signerList[i]->m_signerId);
            if (m_signerList[i]->m_signerId == signerId) return i;
        }
        return -1;
    }


}