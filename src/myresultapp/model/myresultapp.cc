#include  "myresultapp.h"
#include "myConstants.hpp"

using namespace std;
namespace ns3{

MyResultApp::MyResultApp(): Application()
{
  m_nMyForwardedInterest=0;
  m_myTotalInterestOverhead=0;
  m_nMyForwardedData=0;
  m_nMyForwardedIbfInterest=0;
  m_nMyForwardedIbfData=0;
  m_myTotalDataOverhead=0;
  m_myLastInterestForwardTime=0;
  m_myLastDataForwardTime=0;
  m_nMySatisfiedInterests=0;
  m_myTotalDelay=0;
  m_myTotalSignallingOverhead=0;
  m_myTotalInterestIbfSignalingOverhead=0;
  m_myTotalDataIbfSignalingOverhead=0;
  m_nMyForwardedAdverts=0;
  m_myLastAdvertForwardTime=0;
  m_myNumberOfUnsatisfiedInterests=0;
  m_myNumberOfSatisfiedInterests=0;
  m_myNumberOfRetrievedData=0; //only for clients
  m_myNumberOfSP_calculations=0;//only for the SP approach
  m_myTotalSP_calculations_overhead=0;//only for the SP approach
  m_myFirstCarInterestReceptionTime=0;
  m_iReceivedFirstRecentCarInterest=false;
  m_myFirstCarDataReceptionTime=0;
  m_iReceivedFirstRecentCarData=false;
  myIbfFilter= CreateObject<MyBloom_filter> (IBF_PEC, FPP, ns3::UNIVERSAL_SEED);

}

MyResultApp::~MyResultApp()
{}

  void MyResultApp::Start(){
    m_running = true;
    //m_myNodeId=Simulator::GetContext();
  }

  void
  MyResultApp::Stop () {
    m_running = false;
  }

  void
  MyResultApp::InstallEndpointApp2(Ptr<Node> node){
	 // install on consumers and producers
    Ptr<MyResultApp> endPointAppPtr;
    int appIndex=0;


  		endPointAppPtr=CreateObject<MyResultApp> ();
  		appIndex=node->AddApplication(endPointAppPtr);
      NS_LOG_UNCOND ("for End node "<<node->GetId()<<" app index = "<<appIndex);
  		endPointAppPtr->SetNode(node);
      endpointApps.Add(endPointAppPtr);
  		endPointAppPtr->Start();

    allApps.Add (endpointApps);
  }

  void
  MyResultApp::InstallEndpointApp(NodeContainer& nodes)
  {
	  // install on consumers and producers
    Ptr<MyResultApp> endPointAppPtr;
    int appIndex=0;
    size_t N_CONS =0;
    if (IS_GRID){
		N_CONS = N_GRID_CONSUMERS;
	}
	else{
		N_CONS = N_TotalClients;
	}
	std::size_t counter=0;
	if(!IS_GRID){
		counter=N_CONS+N_PRODUCERS;
		}
		else{
			counter=N_CONS;
			}

  	for (size_t i = 0; i < counter ; i++) {
  		endPointAppPtr=CreateObject<MyResultApp> ();
  		appIndex=nodes.Get(i)->AddApplication(endPointAppPtr);
      NS_LOG_UNCOND ("for End node "<<i<<" app index = "<<appIndex);
  		endPointAppPtr->SetNode(nodes.Get(i));
      endpointApps.Add(endPointAppPtr);
  		endPointAppPtr->Start();
  	}
    allApps.Add (endpointApps);
  }

  void
  MyResultApp::InstallEndpointApp_5(NodeContainer& nodes)
  {
    // install on consumers and producers
    Ptr<MyResultApp> endPointAppPtr;
    int appIndex=0;
    size_t N_CONS =0;
    if (IS_GRID){
    N_CONS = N_GRID_CONSUMERS;
  }
  else{
    N_CONS = 5;
  }
  std::size_t counter=0;
  if(!IS_GRID){
    counter=N_CONS+N_PRODUCERS;
    }
    else{
      counter=N_CONS;
      }

    for (size_t i = 0; i < counter ; i++) {
      endPointAppPtr=CreateObject<MyResultApp> ();
      appIndex=nodes.Get(i)->AddApplication(endPointAppPtr);
      NS_LOG_UNCOND ("for End node "<<i<<" app index = "<<appIndex);
      endPointAppPtr->SetNode(nodes.Get(i));
      endpointApps.Add(endPointAppPtr);
      endPointAppPtr->Start();
    }
    allApps.Add (endpointApps);
  }

  void
  MyResultApp::InstallGridRouterApp(PointToPointGridHelper& grid){
	  Ptr<MyResultApp> routerAppPtr;
    int appIndex=0;
    for (size_t i = 0; i < 10 ; i++) {
		for (size_t j = 0; j < 10 ; j++) {
				routerAppPtr=CreateObject<MyResultApp> ();
				appIndex = grid.GetNode(i,j)->AddApplication(routerAppPtr);
				NS_LOG_UNCOND ("for Router node "<<"("<<i<<","<<j<<")"<<" app index = "<<appIndex);
				routerAppPtr->SetNode(grid.GetNode(i,j));
				routerApps.Add(routerAppPtr);
				routerAppPtr->Start();
           }
        }
        allApps.Add(routerApps);
}

 void
 MyResultApp::InstallRouterApp2(Ptr<Node> node){
     Ptr<MyResultApp> routerAppPtr;
      int appIndex=0;

      routerAppPtr=CreateObject<MyResultApp> ();
      appIndex= node->AddApplication(routerAppPtr);
      NS_LOG_UNCOND ("for Router node "<<node->GetId()<<" app index = "<<appIndex);
      routerAppPtr->SetNode(node);
      routerApps.Add(routerAppPtr);
      routerAppPtr->Start();

    allApps.Add(routerApps);

 }

  void
  MyResultApp::InstallRouterApp(AnnotatedTopologyReader& topologyReader) {
    // install app on routers !
    Ptr<MyResultApp> routerAppPtr;
    int appIndex=0;
    for (size_t i = 0; i < N_GEANT_ROUTERS ; i++) {
      routerAppPtr=CreateObject<MyResultApp> ();
      appIndex=topologyReader.GetNodes().Get(i)->AddApplication(routerAppPtr);
      NS_LOG_UNCOND ("for Router node "<<i<<" app index = "<<appIndex);
      routerAppPtr->SetNode(topologyReader.GetNodes().Get(i));
      routerApps.Add(routerAppPtr);
      routerAppPtr->Start();
    }
    allApps.Add(routerApps);
}
}
