#include "ns3/blst.hpp"

using namespace blst;

namespace bls_signatures {
    class SidPkPair
    {
    public:
        P2_Affine m_pk;
        long m_signerId;
    public:
        SidPkPair(long signerId, P2_Affine& pk);
        ~SidPkPair();
    };
    
    SidPkPair::SidPkPair(long signerId, P2_Affine& pk)
    {
        m_pk = *(new P2_Affine(pk));
        m_signerId = signerId;
    }
    
    SidPkPair::~SidPkPair()
    {
        delete &m_pk;
        //m_pk.~P2_Affine();
    }
    
}