#include "ns3/blst.hpp"
#include <string>
#include <stdlib.h>
#include "BloomFilterContainer.hpp"

using namespace blst;

namespace bls_signatures {
    class Interest
    {
    public:
        enum InterestType : char {
            CAR, CA
        };

    private:
        InterestType m_type;
        std::vector<BloomFilterContainer&> m_bloomFilters;
        P1_Affine m_signature;


    public:
        Interest() = delete;
        Interest(InterestType type);
        ~Interest();
        std::string getTypeString();
        InterestType getType() { return m_type; };
    };

    Interest::Interest(InterestType type)
    {
        m_type = type;
    }

    Interest::~Interest()
    {
        m_bloomFilters.~vector();
    }

    std::string Interest::getTypeString()
    {
        switch (m_type)
        {
        case Interest::CAR:
            return "CAR";
        case Interest::CA:
            return "CA";
        default:
            break;
        }
    }

}