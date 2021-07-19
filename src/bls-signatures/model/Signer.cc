#include "Signer.hpp"

namespace bls_signatures {
     Signer::Signer(/* args */)
    {

    }

    Signer::Signer(byte seed[32], size_t size)
    {
        m_sk = new SecretKey();
        m_sk->keygen(seed, size);
        P2 pk(*m_sk);
        m_pk = new P2_Affine(pk);
    }

    Signer::~Signer()
    {
        delete m_pk;
    }

    P2_Affine& Signer::getPublicKey()
    {
        return *m_pk;
    }

    P1& Signer::sign(byte* message, size_t size)
    {
        P1 hash = P1(*m_sk);
        hash.hash_to(message, size);

        return *hash.sign_with(*m_sk);
    }

    P1& Signer::sign(bloom_filter* bf)
    {
        return sign(((byte*)bf->table()), bf->size()/8);    
    }

    P1 Signer::sign(BloomFilterContainer* container)
    {
        P1 signature = sign((container->getBloomFilter()));
        std::vector<BloomFilterContainer*> reconstructed = container->reconstructBfs();
        for (size_t i = 0; i < reconstructed.size() ;i++) {
            signature.aggregate(sign(reconstructed[i]));
        }
        return signature;
    }

    bool Signer::verify(std::vector<SignedMessage> messages, std::vector<P1_Affine> signatures)
    {
        P1_Affine aggregateSignature = aggregateSignatures(signatures);

        Pairing* pairing = new Pairing(1, NULL, 0);
        for (size_t i = 0; i < messages.size(); i++) {
            SignedMessage message = messages[i];
            pairing->aggregate(message.m_publicKey, NULL, message.m_content->table(), message.m_content->size()/8, NULL, 0);
        }

        PT* pt = new PT(aggregateSignature);

        pairing->commit();
        bool res = pairing->finalverify(pt) == 1;

        delete pairing;
        delete pt;
        
        return res;
    }

    bool Signer::verify(byte* message, size_t size, P1_Affine* signature, P2_Affine pk)
    {
        return (signature->core_verify(pk, 1, message, size) == BLST_SUCCESS);
    }

    P1_Affine Signer::aggregateSignatures(std::vector<P1_Affine> signatures)
    {
        std::vector<P1_Affine>::iterator it = signatures.begin();
        P1 res;
        for (std::vector<P1_Affine>::iterator it = signatures.begin(); it < signatures.end(); it++)
        {
            res.aggregate(*it);
        }
        return (res.to_affine());
    }

    // ------------------ Misc --------------------------------
    // delete these later
    void Signer::printByte(unsigned char n)
    {
        blst::byte i = 0;
        while (i < 8) {
            std::printf("%i", n & 1);
            n >>= 1;
            i++;
        }
    }

    void Signer::printFilter(bloom_filter* m_bloomFilter)
    {
        for (unsigned long i = 0; i < m_bloomFilter->size() / 8; i++) {
            //printf("%i", filter->table()[i]);
            printByte(m_bloomFilter->table()[i]);
        }
        std::printf("\n");
    }
}