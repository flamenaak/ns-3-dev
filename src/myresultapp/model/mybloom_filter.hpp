#ifndef INCLUDE_MYBLOOM_FILTER_HPP
#define INCLUDE_MYBLOOM_FILTER_HPP


#include "ns3/random-variable-stream.h"
#include "bloom_filter.hpp"

//using namespace std;
//using namespace ns3;
namespace ns3{

class MyBloom_filter :  public ns3::Object, public bloom_filter {
public:
  MyBloom_filter(const std::size_t& predicted_element_count,
                const double& false_positive_probability,
                const std::size_t& random_seed) : Object(), bloom_filter(predicted_element_count,false_positive_probability, random_seed){};

 //this constructor could be used for easier GETs probably
  MyBloom_filter(const std::size_t& table_size, const std::size_t& salt_count,
               const std::size_t& random_seed, const unsigned char* buffer) : Object(),
               bloom_filter(table_size,salt_count,random_seed,buffer){};

  MyBloom_filter(const bloom_filter& filter): Object(), bloom_filter(filter){};

   ~MyBloom_filter(){};


};

/*inline MyBloom_filter&  operator& (const  MyBloom_filter& filter1, const  MyBloom_filter& filter2){
		ns3::Ptr<MyBloom_filter> bf= CreateObject<MyBloom_filter> (PEC, FPP, UNIVERSAL_SEED);

		return (*bf).operator&(filter1, filter2);
	}*/
}
#endif
