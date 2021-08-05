#include "BlsApp.hpp"

using namespace ns3;

BlsApp::BlsApp(BlsNodeType type) {
    m_carAggregation = false;
    m_caAggregation = false;
    m_nodeType = type;
}

BlsApp::~BlsApp() {
    
}