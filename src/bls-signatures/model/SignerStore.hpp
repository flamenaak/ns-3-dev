#ifndef SIGNER_STORE_H
#define SIGNER_STORE_H

#include "ns3/SidPkPair.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <array>
#include <vector>

using namespace std;
using namespace bls_signatures;

namespace ns3 {
    class SignerStore {
    private:
        vector<SidPkPair*> ids;

    public:
        SignerStore();
        ~SignerStore();
        SidPkPair* getSidPkPair(SignerId id);
        size_t insertPair(SidPkPair* pair);
        void deleteEntry(SignerId id);
        void deleteIndex(SignerId id);

        vector<SidPkPair*> getAllPairs();

    
        size_t getSize();
    };
}

#endif