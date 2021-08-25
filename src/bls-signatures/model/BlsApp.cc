#include "BlsApp.hpp"

using namespace ns3;

BlsApp::BlsApp(BlsNodeType type, SignerId id) {
    m_carAggregation = false;
    m_caAggregation = false;
    m_nodeType = type;
    m_id = id;

    byte seed[32];
    getRandomSeed(seed, 32, id);
    m_signer = Signer(seed,32);
}

BlsApp::~BlsApp() {
    // delete[] m_timeMap;
}

SignerId BlsApp::getId()
{
    return m_id;
}

Signer* BlsApp::getSigner()
{
    return &m_signer;
}

BlsNodeType BlsApp::getNodeType()
{
    return m_nodeType;
}

void BlsApp::getRandomSeed(byte* buffer, size_t size, int seed)
{
  srand(seed);

  for (size_t i = 0; i < size; i++) {
    *(buffer + i) = rand() % 255;
  }
}

SignerStore* BlsApp::getSigners()
{
  return &m_signers;
}

std::map<std::string, int64_t>* BlsApp::getTimeMap()
{
  return &m_timeMap;
}
