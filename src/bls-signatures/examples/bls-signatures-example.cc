/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#include "ns3/core-module.h"
#include "ns3/bls-signatures-helper.h"
#include "ns3/bls-signatures.h"

using namespace ns3;
//using namespace blst;

  int main(int argc, char* argv[])
  {
    // float p = 0.02;
    // int n = 200;
    // int m = 15;
    // int k = 3;

    // srand(25);
    // uint8_t seed[32] = { 0 };
    // SecretKey sk1;

    // /* Generate key pairs. */
    // sk1.keygen(seed, sizeof(seed));
    // printf("Got secret keys \n");

    // /* Hash messages to points in G1. */
    // P1* hash1 = new P1(sk1);
    // printf("Initiated hash \n");

    // P2* pk1 = (new P2(sk1));
    // printf("Got public keys \n");

    // /** Convert public keys to affine points for verification. */
    // P2_Affine* affine_pk1 = new P2_Affine(*pk1);


    Simulator::Run();
    Simulator::Destroy();
    return 0;
  }


