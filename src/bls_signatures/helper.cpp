#include "./blst/bindings/blst.hpp"
#include <iostream>
using namespace std;
using namespace blst;

namespace bls_helper
{

  P1_Affine aggregate_signatures(vector<P1_Affine> signatures)
  {
    vector<P1_Affine>::iterator it = signatures.begin();
    P1 res;
    for (vector<P1_Affine>::iterator it = signatures.begin(); it < signatures.end(); it++)
    {
      res.aggregate(*it);
    }
    return (res.to_affine());
  }
}
