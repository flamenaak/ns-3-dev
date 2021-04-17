#ifndef _MYCONSTANTS_HPP_
#define _MYCONSTANTS_HPP_

using namespace std;
namespace ns3{
static const std::size_t MAX_URL_VARIETY = 1000;
static const std::size_t MAX_SEQ_NUMBER = 100;

static const bool IS_GRID=false;
static const bool IS_BUTT=true;

//test 5 taee
static const bool SMALL_TEST=false;



static const std::string mode = "windowing";// assign "classical" to mode if you like the basic (infocom) approach

static const std:: string CONTENT_UNIVERSE_PATH= "/home/ali/GitHub/Datasets/test/fifty/producers/server_dataset/large_scale/shuffled_content_universe_1000";

static const std:: string FIRST_WIN_UNIVERSE_PATH = "/home/ali/GitHub/Datasets/test/fifty/producers/server_dataset/large_scale/windowing/window_0_shuffled";
static const std:: string SECOND_WIN_UNIVERSE_PATH = "/home/ali/GitHub/Datasets/test/fifty/producers/server_dataset/large_scale/windowing/window_01_shuffled";
static const std:: string THIRD_WIN_UNIVERSE_PATH ="/home/ali/GitHub/Datasets/test/fifty/producers/server_dataset/large_scale/windowing/window_012_shuffled" ;
static const std:: string FOURTH_WIN_UNIVERSE_PATH = "/home/ali/GitHub/Datasets/test/fifty/producers/server_dataset/large_scale/windowing/window_0123_shuffled";
static const std:: string FIFTH_WIN_UNIVERSE_PATH = "/home/ali/GitHub/Datasets/test/fifty/producers/server_dataset/large_scale/windowing/window_01234_shuffled";


static const std:: string BUT_FIRST_WIN_UNIVERSE_PATH = "/home/ali/GitHub/Datasets/test/fifty/producers/server_dataset/large_scale/windowing/but_window_0_shuffled";
static const std:: string BUT_SECOND_WIN_UNIVERSE_PATH = "/home/ali/GitHub/Datasets/test/fifty/producers/server_dataset/large_scale/windowing/but_window_01_shuffled";
static const std:: string BUT_THIRD_WIN_UNIVERSE_PATH ="/home/ali/GitHub/Datasets/test/fifty/producers/server_dataset/large_scale/windowing/but_window_012_shuffled" ;
static const std:: string BUT_FOURTH_WIN_UNIVERSE_PATH = "/home/ali/GitHub/Datasets/test/fifty/producers/server_dataset/large_scale/windowing/but_window_0123_shuffled";
static const std:: string BUT_FIFTH_WIN_UNIVERSE_PATH = "/home/ali/GitHub/Datasets/test/fifty/producers/server_dataset/large_scale/windowing/but_window_01234_shuffled";


//this is only for shortest path
static const std::string SERVERS_DATASETS_PATH = "/home/ali/GitHub/Datasets/test/fifty/producers/server_dataset/large_scale/";

//windowing approach:
static const std::string window_0 = "/home/ali/GitHub/Datasets/test/fifty/producers/server_dataset/large_scale/windowing/window_0_shuffled";
static const std::string window_1 = "/home/ali/GitHub/Datasets/test/fifty/producers/server_dataset/large_scale/windowing/window_1_shuffled";
static const std::string window_2 = "/home/ali/GitHub/Datasets/test/fifty/producers/server_dataset/large_scale/windowing/window_2_shuffled";
static const std::string window_3 = "/home/ali/GitHub/Datasets/test/fifty/producers/server_dataset/large_scale/windowing/window_3_shuffled";
static const std::string window_4 = "/home/ali/GitHub/Datasets/test/fifty/producers/server_dataset/large_scale/windowing/window_4_shuffled";

static const std::size_t N_TotalClients = 50;// total number of clients to be attached.
static const  std::size_t N_PRODUCERS=5;
static const  std::size_t N_GEANT_ROUTERS = 40;
static const size_t N_GRID_CONSUMERS=24;

static const std::size_t N_NODES = N_TotalClients+N_PRODUCERS+N_GEANT_ROUTERS;

static const std::size_t UNIVERSAL_SEED = 10;
static const std::size_t PEC = 200;
static const std::size_t IBF_PEC = 1000;
static const std::size_t CAR_PEC = 100;
static const double FPP = 0.0638;

static const double SIMULATION_TIME=1000;
static const double FIRST_WINDOW_START = 0;
static const double SECOND_WINDOW_START = 200;
static const double THIRD_WINDOW_START = 400;
static const double FOURTH_WINDOW_START = 600;
static const double FIFTH_WINDOW_START = 800;

static const double firstFailureTime=10;
static const double secondFailureTime=210;
static const double thirdFailureTime=410;

static const double firstRecoveryTime=110;
static const double secondRecoveryTime=310;
static const double thirdRecoveryTime=510;

//scenario utils

static const double PATIENCE_FOR_ADVERT_PROPAGATION = 0.1;// 0.1 is enough since 20 and 21 received latest (0.07 s)
static const double CONS_START= PATIENCE_FOR_ADVERT_PROPAGATION;
static const double ADVERT_START=0.0;
static const double PROD_START=0.0;


static const std::string CONSUMER_FREQ = "1";//one interest per sec
static const std::string ADVERT_FREQ = "0.0667";// 1 advert per 15 seconds
static const std::string INVERSE_ADVERT_LIFE_TIME = "0.0167";//advert life time is one minute
static const std::string PAYLOAD_SIZE = "1350";//= around 1.5 Kbytes (max MTU)
static const std::string IBF_LIFE_TIME = "19.95"; // ibf life time around 0.05 seconds
static const std::string IBF_FREQ = "0.05";//1 IBF per 4 seconds
static const std::string INVERSE_IBF_LIFE_TIME = "0.05012";


static const std::string  PROD_LINK_DATA_RATE="1024Mbps";
static const std::string  PROD_LINK_DELAY="2ms";

static const std::string  CONS_LINK_DATA_RATE="24Mbps";
static const std::string  CONS_LINK_DELAY="10ms";

///////////////////////////////////////////
//            ZIPF parameters           //
//////////////////////////////////////////
static const double Q = 0;//parameter of improve rank (nitial value: 0.7 )
static const double S = 1.4;//parameter of power (nitial value: 0.7 )

static const std::string RANDOMIZE_ATTRIBUTE= "exponential";//inter-gap for interest messages, default=none.

static const std::size_t CACHE_SIZE = 100;
static const bool RANDOM_WALK=false;


}
#endif // _MYCONSTANTS_HPP_
