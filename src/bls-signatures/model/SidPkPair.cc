#include "SidPkPair.hpp"

namespace bls_signatures {
    SidPkPair::SidPkPair(SignerId signerId, P2_Affine& pk)
    {
        m_pk = new P2_Affine(pk);
        m_signerId = signerId;
    }

    SidPkPair::~SidPkPair()
    {
        delete m_pk;
        //m_pk.~P2_Affine();
    }
};