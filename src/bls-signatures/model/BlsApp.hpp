#ifndef BLS_APP_H
#define BLS_APP_H

#include "ns3/core-module.h"
#include "ns3/network-module.h"

#include "ns3/types.hpp"
#include "ns3/random-variable-stream.h"
#include "ns3/SidPkPair.hpp"
#include "ns3/Signer.hpp"
#include "ns3/SignerStore.hpp"

using namespace bls_signatures;

namespace ns3 {
    class BlsApp : public Application {
        public: 
            BlsApp(BlsNodeType type, SignerId id);
            ~BlsApp();

            SignerId getId();
            Signer* getSigner();
            BlsNodeType getNodeType();
            SignerStore* getSigners();
            std::map<std::string, int64_t>* getTimeMap();
            
        private:
            void getRandomSeed(byte* buffer, size_t size, int seed);
        
        private:
            BlsNodeType m_nodeType;
            bool m_carAggregation;
            bool m_caAggregation;

            SignerStore m_signers;

            Signer m_signer;
            SignerId m_id;
            std::map<std::string, int64_t> m_timeMap;
    };
}

#endif