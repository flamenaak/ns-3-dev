#include "ns3/SignedMessage.hpp"

namespace bls_signatures {
    SignedMessage::SignedMessage()
    {
        m_content->clear();
    }

    SignedMessage::SignedMessage(bloom_filter* content, P2_Affine* pk)
    {
        m_content = content;
        m_publicKey = pk;
    }

    SignedMessage::~SignedMessage()
    {

    }
}