#ifndef BLS_APP_H
#define BLS_APP_H

#include "ns3/core-module.h"
#include "ns3/network-module.h"

#include "ns3/types.hpp"
#include "ns3/random-variable-stream.h"
#include "ns3/SidPkPair.hpp"

using namespace bls_signatures;

namespace ns3 {
    class BlsApp : public Application {
        public: 
            BlsApp(BlsNodeType type);
            ~BlsApp();
        public:
            BlsNodeType m_nodeType;
            bool m_carAggregation;
            bool m_caAggregation;
    };
}

#endif