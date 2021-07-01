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
        byte* serialize();
        void deserialize(byte* data);

    public:
        bloom_filter *m_content;
        P2_Affine *m_publicKey;
    };
    SignedMessage::SignedMessage()
    {
        m_content->clear();
    }

    SignedMessage::SignedMessage(bloom_filter *content, P2_Affine *pk)
    {
        m_content = content;
        m_publicKey = pk;
    }

    SignedMessage::~SignedMessage()
    {
        delete m_publicKey;
        delete m_content;
    }

    byte* serialize()
    {
        return {0};
    }
    
    void deserialize(byte* data)
    {

    }

}

#endif