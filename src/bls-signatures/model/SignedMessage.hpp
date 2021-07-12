#ifndef SIGNED_MESSAGE_H
#define SIGNED_MESSAGE_H

#include <stdlib.h>
#include "ns3/blst.h"
#include "ns3/myresultapp.h"

using namespace blst;

namespace bls_signatures {
    class SignedMessage
    {
    private:

    public:
        SignedMessage(/* args */);
        SignedMessage(bloom_filter *content, P2_Affine *pk);
        ~SignedMessage();

    public:
        bloom_filter *m_content;
        P2_Affine *m_publicKey;
    };
}

#endif