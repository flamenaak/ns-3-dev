/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#include "ns3/core-module.h"
#include "ns3/bls-signatures-helper.h"
#include "ns3/blst.h"
#include "ns3/myresultapp.h"
#include <stdio.h>
#include <stdlib.h>
#include <array>
#include <assert.h>


#include "ns3/SidPkPair.hpp"
#include "ns3/SignedMessage.hpp"
#include "ns3/BloomFilterReduction.hpp"
#include "ns3/BloomFilterContainer.hpp"
#include "ns3/types.hpp"

using namespace ns3;
using namespace blst;
using namespace bls_signatures;
//using namespace std;

void printByte(unsigned char n)
{
  byte i = 0;
  while (i < 8) {
    printf("%li", n & 1);
    n >>= 1;
    i++;
  }
}

void printFilter(bloom_filter* filter)
{
  for (unsigned long i = 0; i < filter->size(); i++) {
    //printf("%i", filter->table()[i]);
    printByte(filter->table()[i]);
  }
  printf("\n");
}

unsigned int countSetBitsInChar(unsigned char n)
{
  unsigned char count = 0;
  while (n) {
    count += n & 1;
    n >>= 1;
  }
  return count;
}

unsigned long countSetBits(bloom_filter* filter)
{
  unsigned long count = 0;
  for (unsigned long i = 0; i < filter->size(); i++) {
    count += countSetBitsInChar(filter->table()[i]);
  }
  return count;
}

int main(int argc, char* argv[])
{
  float p = 0.5;
  int n = 5;
  // int m = 15;
  // int k = 3;

  srand(25);
  uint8_t seed[32] = { 0 };
  SecretKey sk1 = {};

  /* Generate key pairs. */
  sk1.keygen(seed, sizeof(seed));
  printf("Got secret keys \n");

  /* Hash messages to points in G1. */
  P1* hash1 = new P1(sk1);
  printf("Initiated hash \n");

  P2* pk1 = (new P2(sk1));

  printf("Got public key \n");

  /** Convert public keys to affine points for verification. */
  P2_Affine* affine_pk1 = new P2_Affine(*pk1);
  std::vector<byte> arr = std::vector<byte>();
  arr.reserve(192);
  affine_pk1->serialize(arr.data());
  printf("pk: %s \n", arr.data());

  // Test SidPkPair
  SidPkPair pair1((long)123, *affine_pk1);
  printf("signer id: %li \n", pair1.m_signerId);
  //printf("public key: %s \n", charr);


  // Test SignedMessage
  bloom_filter* filter1 = new bloom_filter(n, p, ns3::UNIVERSAL_SEED);
  bloom_filter* filter3 = new bloom_filter(n, p, ns3::UNIVERSAL_SEED);
  bloom_filter* filterXor = new bloom_filter(n, p, ns3::UNIVERSAL_SEED);
  printf("filter1 size: %lu \n", filter1->size());
  printf("filter3 size: %lu \n", filter3->size());
  filter1->clear();
  filter3->clear();

  string str1 = "content1";
  filter1->insert(str1);
  *filterXor = *filter1 ^= *filter3;
  printFilter(filter1);
  printFilter(filter3);
  printFilter(filterXor);

  printf("set bits in filter1: %lu \n", countSetBits(filter1));
  printf("set bits in filter3: %lu \n", countSetBits(filter3));
  printf("set bit in filter xor: %lu \n", countSetBits(filterXor));

  SignedMessage msg1(filter1, affine_pk1);
  assert(msg1.m_content->contains(str1));
  assert(msg1.m_publicKey->is_equal(*affine_pk1));

  // Test BloomFilterReduction
  std::vector<long> indexes = { 0,15,22,36,45 };
  BloomFilterReduction reduction(pair1.m_signerId, indexes);
  assert(pair1.m_signerId == reduction.getSignerId());

  // Test BloomFilterContainer
  bloom_filter* filter2 = new bloom_filter(n, p, ns3::UNIVERSAL_SEED);
  string str2 = "content1";
  filter2->insert(str2);
  BloomFilterContainer bfContainer((long)555, filter2);
  bfContainer.addReduction(&reduction);

  assert(bfContainer.getReductions().size() > 0);
  assert((bfContainer.getReductions()[0])->getIndexVector() == reduction.getIndexVector());
  assert(bfContainer.getSignerId() == (long)555);

  // Test BloomFIlterContainer distance calculation
  BloomFilterContainer bfContainer2((long)555, filter1);
  printf("distance of bfContainer: %lu \n",bfContainer2.calculateDistance(filter3));

  // Test BFContainer addReduction(*bf)
  bfContainer2.addReduction(filter3, (SignerId)111);
  printf("size of reductions: %lu \n", bfContainer.getReductions().size());
  bfContainer2.getReductions()[0]->printIndexVector();


  printf("done \n");

  Simulator::Run();
  Simulator::Destroy();
  return 0;
}
