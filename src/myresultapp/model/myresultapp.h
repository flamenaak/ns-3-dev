
#ifndef MY_RESULT_APP_H
#define MY_RESULT_APP_H

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/random-variable-stream.h"
#include "/home/vlado/ndnSIM/ns-3/src/ndnSIM/utils/topology/annotated-topology-reader.hpp"
#include "myConstants.hpp"
#include "mybloom_filter.hpp"
//#include "point-to-point-grid.h"
#include "ns3/point-to-point-layout-module.h"
//#include "ns3/ndnSIM-module.h"

namespace ns3{

  class MyResultApp : public Application
  {
  public:
     MyResultApp();
    ~MyResultApp();
    void Start();
    void Stop();
    void InstallEndpointApp(NodeContainer& nodes);
    void InstallEndpointApp_5(NodeContainer& nodes);
    void InstallEndpointApp2(Ptr<Node> node);
    void InstallRouterApp(AnnotatedTopologyReader& topologyReader);
    void InstallRouterApp2(Ptr<Node> node);
        void InstallGridRouterApp(PointToPointGridHelper& grid);

  public:
    bool m_running;
    uint16_t m_myNodeId;
    uint64_t m_nMyForwardedInterest;
    long int  m_nMyForwardedIbfInterest;
    long int  m_nMyForwardedIbfData;
    uint64_t m_nMySatisfiedInterests;
    uint64_t m_myTotalDelay;
    uint64_t m_myTotalInterestOverhead;
    uint64_t m_nMyForwardedData;
    uint64_t m_myTotalDataOverhead;
    uint64_t m_nMyForwardedAdverts;
    double m_myLastInterestForwardTime;
    double m_myLastDataForwardTime;
    long double m_myTotalSignallingOverhead;
    long double m_myTotalInterestIbfSignalingOverhead;
    long double m_myTotalDataIbfSignalingOverhead;
    double m_myLastAdvertForwardTime;
    uint64_t m_myNumberOfUnsatisfiedInterests;
    uint64_t m_myNumberOfSatisfiedInterests;
    uint64_t m_myNumberOfRetrievedData;//only for clients
    uint64_t m_myNumberOfSP_calculations;
    uint64_t m_myTotalSP_calculations_overhead;
    double m_myFirstCarInterestReceptionTime;
    bool m_iReceivedFirstRecentCarInterest;
    double m_myFirstCarDataReceptionTime;
    bool m_iReceivedFirstRecentCarData;
    ApplicationContainer endpointApps, routerApps, allApps;

    Ptr<MyBloom_filter> myIbfFilter;
  };

}
#endif
