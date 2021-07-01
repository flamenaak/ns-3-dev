#ifndef BF_REDUCTION_H
#define BF_REDUCTION_H

#include <stdlib.h>
#include <stdio.h>
#include "types.hpp"

namespace bls_signatures {
    
    class BloomFilterReduction
    {
    private:
        SignerId m_signerId;
        std::vector<BfIndex> m_indexVector;
    public:
        BloomFilterReduction(/* args */);
        BloomFilterReduction(SignerId sid, std::vector<BfIndex> indexVector);
        ~BloomFilterReduction();
        SignerId getSignerId();
        std::vector<BfIndex> getIndexVector();
        void printIndexVector();
        
    };

    BloomFilterReduction::BloomFilterReduction(/* args */)
    {
        m_indexVector.clear();
        m_signerId = 0;
    }

    BloomFilterReduction::BloomFilterReduction(SignerId sid, std::vector<BfIndex> indexVector)
    {
        m_indexVector = indexVector;
        m_signerId = sid;
    }

    BloomFilterReduction::~BloomFilterReduction()
    {
        // delete *m_indexVector;
    }

    SignerId BloomFilterReduction::getSignerId()
    {
        return m_signerId;
    }

    std::vector<BfIndex> BloomFilterReduction::getIndexVector()
    {
        return m_indexVector;
    }

    void BloomFilterReduction::printIndexVector()
    {
        printf("printing index vector \n");
        for(std::vector<BfIndex>::iterator it = std::begin(m_indexVector); it != std::end(m_indexVector); ++it) {
            std::cout << *it;
        }
        printf("\n");
    }
}

#endif