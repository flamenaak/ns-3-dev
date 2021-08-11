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
            CA,
            content
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
        std::string getTypeString();
        InterestType getInterestType() const;
        std::vector<BloomFilterContainer *> getBloomFilters();
        std::vector<SidPkPair *> getSignerList();
        void addSigner(SidPkPair *signerPair);
        P1_Affine *getSignature();
        void setInterestType(const InterestType& newType);
        void setSignature(P1_Affine* newSignaturePtr);


        void merge(BlsInterest *other);
        void merge(BlsInterest *other, vector<SidPkPair *> additionalSignerList);
        void mergeBf(BloomFilterContainer *bloomFilter);
        void addBloomFilter(BloomFilterContainer *bf);
        vector<BloomFilterContainer*> getAllBloomFilters();
        bool verify(vector<SidPkPair*> additionalSignerList);
        size_t getPublicKeyIndex(SignerId signerId);
        size_t searchForPk(SignerId signerId, vector<SidPkPair*> list);

        size_t estimateByteSize(bool log);
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

 // BLS signature methods implementation
  std::string BlsInterest::getTypeString()
  {
    switch (m_type)
    {
    case BlsInterest::CAR:
      return "CAR";
    case BlsInterest::CA:
      return "CA";
    case BlsInterest::content:
      return "content";
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

  vector<BloomFilterContainer*> BlsInterest::getAllBloomFilters()
  {
    vector<BloomFilterContainer* > result;

    for (size_t i = 0; i < m_bloomFilters.size(); i++) {
      BloomFilterContainer *current = m_bloomFilters[i];
      result.push_back(new BloomFilterContainer(current->getSignerId(), *(current->getBloomFilter())));
      vector<BloomFilterContainer *> tempBfs = current->reconstructBfs();
      result.insert(result.end(), tempBfs.begin(), tempBfs.end());
    }

    return result;
  }

  std::vector<SidPkPair*> BlsInterest::getSignerList()
  {
    return m_signerList;
  }

  BlsInterest::InterestType BlsInterest::getInterestType() const
  {
    return m_type;
  }

  void BlsInterest::setInterestType(const BlsInterest::InterestType& type)
  {
    m_type = type;
  }

  void BlsInterest::setSignature(blst::P1_Affine *signature) 
  {
    m_signature = signature;
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

  void BlsInterest::mergeBf(BloomFilterContainer* bloomFilter)
  {
    //printf("mergeBf: entered method \n");
    if (m_bloomFilters.size() == 0)
    {
      m_bloomFilters.push_back(bloomFilter);
      return;
    }
    // find the closest bloomFilter
    unsigned long minDistance = -1;
    BloomFilterContainer* closestBloomFilter;
    size_t index = 0;
    //printf("mergeBf: size of m_bloomFilters %lu \n", m_bloomFilters.size());
    for (size_t i = 0; i < m_bloomFilters.size(); i++) {
      unsigned long distance = m_bloomFilters[i]->calculateDistance(bloomFilter->getBloomFilter());
      if (minDistance == (unsigned long)-1 || distance < minDistance) {
        minDistance = distance;
        closestBloomFilter = m_bloomFilters[i];
        index = i;
      }
    }
    if (minDistance == -1) {
      m_bloomFilters.push_back(bloomFilter);
    }
    //printf("mergeBf: finished finding nearest \n");
    if (minDistance <= (unsigned long)DELTA_MAX) {
      if (closestBloomFilter->merge(bloomFilter)) {
        return;
      }
      else if (bloomFilter->merge(closestBloomFilter)) {
        m_bloomFilters[index] = bloomFilter;
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

  void BlsInterest::merge(BlsInterest* other)
  {
    if (m_type != other->getInterestType()) {
      printf("not merging, wrong type \n");
      return;
    }

    if (other->getBloomFilters().size() == 0) {
      printf("not merging, no bloom filters \n");
      return;
    }

    // this is probably not necessary, received interests are already verified
    
    // if (!other->verify(additionalSignerList)) {
    //   printf("could not verify BlsInterest being merged \n");
    //   return;
    // }

    for (size_t i = 0; i < other->getBloomFilters().size(); i++) {
      mergeBf(other->getBloomFilters()[i]);
    }
    // merge the signer lists
    for (size_t i = 0; i < other->getSignerList().size(); i++) {
      addSigner(other->getSignerList()[i]);
    }

    P1 temp = P1(*m_signature);
    temp.aggregate(*other->getSignature());
    m_signature = new P1_Affine(temp);
  }

  bool BlsInterest::verify(vector<SidPkPair*> additionalSignerList)
  {
    if (m_signature == NULL) return false;
    
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
          reductionIndex = searchForPk(reduction->getSignerId(), additionalSignerList);
        }
        if (reductionIndex == (size_t)-1) {
          printf("did not find public key of a reduction for SignerId %lu \n", reduction->getSignerId());
          return false;
        }
        messages.push_back(SignedMessage(reduction->getBloomFilter(), m_signerList[reductionIndex]->m_pk));
      }
    }
    return Signer::verify(messages, signatures);
  }

  // extend this when you have a public key cache
  size_t BlsInterest::getPublicKeyIndex(SignerId signerId)
  {
    return searchForPk(signerId, m_signerList);
  }

  size_t BlsInterest::searchForPk(SignerId signerId, vector<SidPkPair*> list)
  {
    for (size_t i = 0; i < list.size(); i++) {
      //printf("index %lu, signer id %lu \n", i, m_signerList[i]->m_signerId);
      if (list[i]->m_signerId == signerId) return i;
    }
    return -1;
  }

  size_t BlsInterest::estimateByteSize(bool log)
  {
    size_t reductionCount = 0;
    size_t size = 0;
    for (size_t i = 0; i < m_bloomFilters.size(); i++)
    {
      if (log)
        printf("Estimating byte size: adding %lu \n", m_bloomFilters[i]->getByteSize());
      size += m_bloomFilters[i]->getByteSize();
      reductionCount += m_bloomFilters[i]->getReductions().size();
    }
    if (log)
      printf("Estimating byte size: have %lu bf containers and %lu reductions \n", m_bloomFilters.size(), reductionCount);

    size += m_signerList.size() * 192; // for the signer list
    size += 96; // for the signature
    size += 100; // other stuff

    return size;
  }
}