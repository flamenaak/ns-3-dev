#include "ns3/blst.h"
#include "ns3/blst.hpp"

#include <string>
#include <stdlib.h>
#include "ns3/BloomFilterContainer.hpp"
#include "ns3/types.hpp"
#include "ns3/Signer.hpp"
#include "ns3/SidPkPair.hpp"
#include "ns3/Interest.hpp"

using namespace blst;

namespace ndn {
    std::string Interest::getTypeString()
    {
        switch (m_type)
        {
        case Interest::CAR:
            return "CAR";
        case Interest::CA:
            return "CA";
        default:
            break;
        }
        return "";
    }

    std::vector<BloomFilterContainer*> Interest::getBloomFilters()
    {
        return m_bloomFilters;
    }

    P1_Affine* Interest::getSignature()
    {
        return m_signature;
    }

    void Interest::addBloomFilter(BloomFilterContainer* bf)
    {
        m_bloomFilters.push_back(bf);
    }

    std::vector<SidPkPair*> Interest::getSignerList()
    {
        return m_signerList;
    }

    /**
     * @brief adds a new SidPkPair into the signer list avoiding adding duplicates based on SignerId
     * 
     * @param signerPair 
     */
    void Interest::addSigner(SidPkPair* signerPair)
    {
        for (size_t i = 0; i < m_signerList.size(); i++) {
            if (signerPair->m_signerId == m_signerList[i]->m_signerId) return;
        }
        m_signerList.push_back(signerPair);
    }

    void Interest::merge(Interest* other)
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
            printf("could not verify Interest being merged \n");
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

    bool Interest::verify()
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

    size_t Interest::getPublicKeyIndex(SignerId signerId)
    {
        for (size_t i = 0; i < m_signerList.size(); i++) {
            //printf("index %lu, signer id %lu \n", i, m_signerList[i]->m_signerId);
            if (m_signerList[i]->m_signerId == signerId) return i;
        }
        return -1;
    }
}