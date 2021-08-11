#include "ns3/SignerStore.hpp"

using namespace bls_signatures;
namespace ns3
{
    SignerStore::SignerStore()
    {
        ids.clear();
    }

    SignerStore::~SignerStore()
    {
        printf("destructing signerStore \n");
        for (size_t i = 0; i < ids.size(); i++)
        {
            delete ids.at(i);
        }
        ids.clear();
    }

    SidPkPair* SignerStore::getSidPkPair(SignerId id)
    {
        for (size_t i = 0; i < ids.size(); i++) 
        {
            if (ids[i]->m_signerId == id)
                return ids[i];
        }
        return NULL;
    }

    size_t SignerStore::insertPair(SidPkPair *pair)
    {
        SidPkPair *newPair = new SidPkPair(pair->m_signerId, pair->m_pk);
        ids.push_back(newPair);
        return ids.size()-1;
    }

    void SignerStore::deleteEntry(SignerId id)
    {
    }

    void SignerStore::deleteIndex(SignerId id)
    {
    }

    size_t SignerStore::getSize()
    {
        return ids.size();
    }

    vector<SidPkPair*> SignerStore::getAllPairs()
    {
        return ids;
    }
}