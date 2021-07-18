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
#include "ns3/BfXorRepresentation.hpp"
#include "ns3/BloomFilterContainer.hpp"
#include "ns3/Signer.hpp"
#include "ns3/BlsInterest.hpp"
#include "ns3/types.hpp"

using namespace ns3;
using namespace blst;
using namespace bls_signatures;
//using namespace std;

void printByte(unsigned char n)
{
  byte i = 0;
  while (i < 8) {
    printf("%i", n & 1);
    n >>= 1;
    i++;
  }
}

void printFilter(bloom_filter* filter)
{
  for (unsigned long i = 0; i < filter->size() / 8; i++) {
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
  for (unsigned long i = 0; i < filter->size() / 8; i++) {
    count += countSetBitsInChar(filter->table()[i]);
  }
  return count;
}

void getRandomSeed(byte* buffer, size_t size, int seed)
{
  srand(seed);

  for (size_t i = 0; i < size; i++) {
    *(buffer + i) = rand() % 255;
  }
}

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

void testEncryption()
{
  printf("\n \n Testing simple signing and aggregating \n");
  srand(0);
  uint8_t seed1[32];
  uint8_t seed2[32];
  getRandomSeed(seed1, sizeof(seed1), rand());
  getRandomSeed(seed2, sizeof(seed2), rand());
  SecretKey sk1, sk2;

  /* Generate key pairs. */
  sk1.keygen(seed1, sizeof(seed1));
  sk2.keygen(seed2, sizeof(seed2));

  printf("secret key sk1: %hu \n", *sk1.key.b);
  printf("secret key sk2: %hu \n", *sk2.key.b);
  //printf("secret keys are equla %s \n", sk1.key==sk2.key);

  printf("Got secret keys \n");

  P2* pk1 = new P2(sk1);
  P2* pk2 = new P2(sk2);

  printf("Got public key \n");

  /** Convert public keys to affine points for verification. */
  P2_Affine* affine_pk1 = new P2_Affine(*pk1);
  P2_Affine* affine_pk2 = new P2_Affine(*pk2);

  // printing of public key bellow

  // std::vector<byte> arr = std::vector<byte>();
  // arr.reserve(192);
  // affine_pk1->serialize(arr.data());
  // printf("pk: %s \n", arr.data());

  // Test SidPkPair
  SidPkPair pair1((long)123, *affine_pk1);
  printf("signer id: %li \n", pair1.m_signerId);
  //printf("public key: %s \n", charr);


  // Test SignedMessage
  bloom_filter* filter1 = new bloom_filter(BF_N, BF_P, BF_SEED);
  bloom_filter* filter2 = new bloom_filter(BF_N, BF_P, BF_SEED);
  bloom_filter* filter3 = new bloom_filter(BF_N, BF_P, BF_SEED);

  printf("filter1 size: %lu \n", filter1->size());
  printf("filter3 size: %lu \n", filter3->size());
  filter1->clear();
  filter2->clear();
  filter3->clear();

  string str1 = "content1";
  string str2 = "content2342112124";
  string str3 = "content that should be very different";

  filter1->insert(str1);
  filter2->insert(str2);
  filter3->insert(str3);

  printFilter(filter1);
  printFilter(filter2);
  printFilter(filter3);

  printf("set bits in filter1: %lu \n", countSetBits(filter1));
  printf("set bits in filter3: %lu \n", countSetBits(filter3));

  SignedMessage msg1(filter1, affine_pk1);
  assert(msg1.m_content->contains(str1));
  assert(msg1.m_publicKey->is_equal(*affine_pk1));

  /* Hash messages to points in G1. */
  P1* hash1 = new P1(sk1);
  P1* hash2 = new P1(sk2);

  hash1->hash_to(filter1->bit_table_, sizeof(filter1->bit_table_));
  hash2->hash_to(filter3->bit_table_, sizeof(filter3->bit_table_));
  printf("Initiated hash \n");

  P1* sig1 = hash1->sign_with(sk1);
  P1* sig2 = hash2->sign_with(sk2);
  printf("Signed the hash \n");

  /* If signatures are valid individually these will pass. */
  P1_Affine* affine_signature1 = new P1_Affine(*sig1);
  P1_Affine* affine_signature2 = new P1_Affine(*sig2);

  assert(affine_signature1->core_verify(*affine_pk1, 1, filter1->bit_table_, sizeof(filter1->bit_table_)) == BLST_SUCCESS);
  assert(affine_signature2->core_verify(*affine_pk2, 1, filter3->bit_table_, sizeof(filter3->bit_table_)) == BLST_SUCCESS);

  vector<P1_Affine> list;
  list.push_back(*affine_signature1);
  list.push_back(*affine_signature2);

  P1_Affine aggregated_signature = aggregate_signatures(list);
  assert(aggregated_signature.in_group() == 1);

  // /* Verify aggregated signatures. */
  Pairing* pairing = new Pairing(1, NULL, 0);
  pairing->aggregate(affine_pk1, NULL, filter1->bit_table_, sizeof(filter1->bit_table_), NULL, 0);
  pairing->aggregate(affine_pk2, NULL, filter3->bit_table_, sizeof(filter3->bit_table_), NULL, 0);

  PT* pt = new PT(aggregated_signature);

  pairing->commit();
  assert(pairing->finalverify(pt) == 1);
}

void testBfReductions()
{
  printf("\n \n Testing BfReduction constructors \n");
  std::vector<BfIndex> indexes = { 0, 2, 7 };
  BfXorRepresentation reduction((SignerId)123, indexes, (size_t)1);
  assert(123 == reduction.getSignerId());
}

void testBfReductionSerDeser()
{
  BfXorRepresentation reduction((SignerId)123, std::vector<BfIndex>({ 0,1,2 }), (size_t)1);
  printf("\n \n Test BfXorRepresentation serialization + deserialization \n");
  printf("original \n");
  printf("size of reduction: %li and signerId: %li \n", reduction.getByteSize(), reduction.getSignerId());
  reduction.printIndexVector();
  unsigned char buffer[reduction.getByteSize()];
  reduction.serialize(buffer, sizeof(buffer));

  BfXorRepresentation reduction2 = BfXorRepresentation();
  reduction2.deserialize(buffer);
  printf("size of reduction2: %li signerId: %li \n", reduction2.getByteSize(), reduction.getSignerId());
  reduction2.printIndexVector();
}

void testBfContainer()
{
#pragma region setup
  //setup
  bloom_filter* filter1 = new bloom_filter(BF_N, BF_P, BF_SEED);
  bloom_filter* filter2 = new bloom_filter(BF_N, BF_P, BF_SEED);
  bloom_filter* filter3 = new bloom_filter(BF_N, BF_P, BF_SEED);
  filter1->clear();
  filter2->clear();
  filter3->clear();
  string str1 = "content1";
  string str2 = "some other string which hashes different";
  string str3 = "content that should be very different";
  filter1->insert(str1);
  filter2->insert(str2);
  filter3->insert(str3);

  srand(25);
  uint8_t seed[32] = { 0 };
  //Setup signatures
  SecretKey sk1, sk2, sk3;

  /* Generate key pairs. */
  sk1.keygen(seed, sizeof(seed));
  sk2.keygen(seed, sizeof(seed));
  sk3.keygen(seed, sizeof(seed));
  P2* pk1 = new P2(sk1);
  P2* pk2 = new P2(sk2);
  P2* pk3 = new P2(sk3);

  /** Convert public keys to affine points for verification. */
  P2_Affine* affine_pk1 = new P2_Affine(*pk1);
  P2_Affine* affine_pk2 = new P2_Affine(*pk2);
  P2_Affine* affine_pk3 = new P2_Affine(*pk3);

  /* Hash messages to points in G1. */
  P1* hash1 = new P1(sk1);
  P1* hash2 = new P1(sk2);
  P1* hash3 = new P1(sk3);

  hash1->hash_to(filter1->table(), filter1->size() / 8);
  hash2->hash_to(filter2->table(), filter2->size() / 8);
  hash3->hash_to(filter3->table(), filter3->size() / 8);

  P1* sig1 = hash1->sign_with(sk1);
  P1* sig2 = hash2->sign_with(sk2);
  P1* sig3 = hash3->sign_with(sk3);

  /* If signatures are valid individually these will pass. */
  P1_Affine* affine_signature1 = new P1_Affine(*sig1);
  P1_Affine* affine_signature2 = new P1_Affine(*sig2);
  P1_Affine* affine_signature3 = new P1_Affine(*sig3);

  assert(affine_signature1->core_verify(*affine_pk1, 1, filter1->table(), filter1->size() / 8) == BLST_SUCCESS);
  assert(affine_signature2->core_verify(*affine_pk2, 1, filter2->table(), filter2->size() / 8) == BLST_SUCCESS);
  assert(affine_signature3->core_verify(*affine_pk3, 1, filter3->table(), filter3->size() / 8) == BLST_SUCCESS);

  vector<P1_Affine> list;
  list.push_back(*affine_signature1);
  list.push_back(*affine_signature2);
  list.push_back(*affine_signature3);

  P1_Affine aggregated_signature = aggregate_signatures(list);
  assert(aggregated_signature.in_group() == 1);
#pragma endregion

  // test memory management
  printf("\n \n Test BloomFilterContainer \n");
  BloomFilterContainer bfContainer((long)555, *filter2);
  BfXorRepresentation reduction((SignerId)123, std::vector<BfIndex>({ 0,1,2 }), (size_t)1);
  bfContainer.addReduction(&reduction);
  assert(bfContainer.getReductions().size() > 0);
  assert((bfContainer.getReductions()[0])->getIndexVector() == reduction.getIndexVector());
  assert(bfContainer.getSignerId() == (long)555);

  // Test BloomFilterContainer distance calculation
  printf("\n \n Test BloomFIlterContainer distance calculation \n");
  BloomFilterContainer bfContainer2((long)555, *filter1);
  printf("distance of bfContainer: %lu \n", bfContainer2.calculateDistance(filter2));

  // Test BFContainer addReduction(*bf)
  printf("\n \n Test BFContainer addReduction(*bf) \n");
  BloomFilterContainer contWithReductions((SignerId)222, *filter1);
  printf("Original filter: ");
  contWithReductions.printFilter();
  contWithReductions.addReduction(filter2, (SignerId)111);
  printf("Adding a reduction of filter: \n");
  printFilter(filter2);
  //bfContainer2.addReduction(&reduction);
  printf("size of reductions: %lu \n", contWithReductions.getReductions().size());
  contWithReductions.getReductions()[0]->printIndexVector();

  printf("\n \n Test BFContainer merge() with identical container\n");
  BloomFilterContainer identCont((long)321, *filter1);
  BloomFilterContainer identCont2((long)654, *filter1);
  BloomFilterContainer identCont3((long)450, *filter1);
  assert(identCont.merge(&identCont2));
  printf("reduction size %lu \n", identCont.getReductions().size());
  assert(identCont.getReductions().size() == 1);
  assert(identCont.getReductions()[0]->getIndexVector().size() == 0);

  assert(identCont3.getReductions().size() == 0);
  identCont2.addReduction(filter2, (SignerId)987);
  assert(identCont3.merge(&identCont2));
  printf("reduction size %lu \n", identCont3.getReductions().size());
  assert(identCont3.getReductions().size() == 2);
  assert(identCont3.getReductions()[0]->equals(identCont2.getReductions()[0]));
  assert(identCont3.getReductions()[1]->getIndexVector().size() == 0);


  // Test BFContainer reconstructReductions
  printf("\n \n Tests of reconstruction \n");
  std::vector<BloomFilterContainer*> reconstructed = contWithReductions.reconstructBfs();
  assert(reconstructed.size() == contWithReductions.getReductions().size());

  bloom_filter* filter4;
  for (size_t i = 0; i < reconstructed.size(); i++) {
    printf("Printing reconstructed with id %lu \n", reconstructed[i]->getSignerId());
    reconstructed[i]->printFilter();
    if (reconstructed[i]->getSignerId() == (SignerId)111) {
      filter4 = reconstructed[i]->getBloomFilter();
    }
    printf("\n");
  }
  printf("\n \n");

  printFilter(filter2);
  printFilter(filter4);
  // filter4 should be equal to filter3 after being reconstructed, so this verification should still work
  Pairing* pairing2 = new Pairing(1, NULL, 0);
  pairing2->aggregate(affine_pk1, NULL, filter1->table(), filter1->size() / 8, NULL, 0);
  pairing2->aggregate(affine_pk2, NULL, filter4->table(), filter4->size() / 8, NULL, 0);

  vector<P1_Affine> list2;
  list2.push_back(*affine_signature1);
  list2.push_back(*affine_signature2);
  P1_Affine aggregate_signature2 = aggregate_signatures(list2);
  PT* pt2 = new PT(aggregate_signature2);

  pairing2->commit();
  assert(pairing2->finalverify(pt2) == 1);
}

void testBfContainerSerDeser()
{
#pragma region init_bloomfilters
  bloom_filter* filter1 = new bloom_filter(BF_N, BF_P, BF_SEED);
  bloom_filter* filter2 = new bloom_filter(BF_N, BF_P, BF_SEED);
  bloom_filter* filter3 = new bloom_filter(BF_N, BF_P, BF_SEED);

  printf("filter1 size: %lu \n", filter1->size());
  printf("filter3 size: %lu \n", filter3->size());
  filter1->clear();
  filter2->clear();
  filter3->clear();

  string str1 = "content1";
  string str2 = "content2342112124";
  string str3 = "content that should be very different";

  filter1->insert(str1);
  filter2->insert(str2);
  filter3->insert(str3);
#pragma endregion


  BloomFilterContainer bfContainer1((SignerId)111, *filter1);

  printf("\n \n Test BfContainer serialize + deserialize \n");
  bfContainer1.addReduction(filter2, (SignerId)222);
  bfContainer1.addReduction(filter3, (SignerId)333);
  unsigned char bfContainerBuffer[bfContainer1.getByteSize()];
  bfContainer1.serialize(bfContainerBuffer, bfContainer1.getByteSize());
  printf("size of bfContainer1: %li and signerId: %li and size of bfContainerBuffer: %li \n", bfContainer1.getByteSize(), bfContainer1.getSignerId(), sizeof(bfContainerBuffer));
  BloomFilterContainer bfContainer2 = BloomFilterContainer();
  bfContainer2.deserialize(bfContainerBuffer);
  printf("size of bfContainer2: %li and signerId: %li \n", bfContainer2.getByteSize(), bfContainer2.getSignerId());


  assert(bfContainer1.getReductions().size() == bfContainer2.getReductions().size());

  for (size_t i = 0; i < bfContainer2.getReductions().size(); i++) {
    BfXorRepresentation* reduction1 = bfContainer1.getReductions()[i];
    BfXorRepresentation* reduction2 = bfContainer2.getReductions()[i];

    assert(reduction1->equals(reduction2));
  }
  assert(bfContainer1.equals(&bfContainer2));

  //assert(bfContainer1.getBloomFilter()->operator==(*(bfContainer2.getBloomFilter())));

  printf("bit table of bfContainer2: \n");
  bfContainer2.printFilter();
  printf("bit table of bfContainer1: \n");
  bfContainer1.printFilter();
}

void testSidPkPair()
{
  printf("\n \n Testing of SidPkPair \n");
  srand(0);
  uint8_t seed1[32];
  uint8_t seed2[32];
  getRandomSeed(seed1, sizeof(seed1), rand());
  getRandomSeed(seed2, sizeof(seed2), rand());
  SecretKey sk1, sk2;

  /* Generate key pairs. */
  sk1.keygen(seed1, sizeof(seed1));
  sk2.keygen(seed2, sizeof(seed2));

  P2* pk1 = new P2(sk1);
  P2* pk2 = new P2(sk2);

  P2_Affine* affine_pk1 = new P2_Affine(*pk1);
  P2_Affine* affine_pk2 = new P2_Affine(*pk2);

  SidPkPair pair1((SignerId)111, *affine_pk1);
  SidPkPair pair2((SignerId)222, *affine_pk2);
  SidPkPair pair4((SignerId)111, *affine_pk2);

  printf("initialized everything \n");

  assert(pair1.equals(&pair1));
  assert(!pair1.equals(&pair2));
  assert(!pair1.equals(&pair4));

  printf("equals method work \n");

  SidPkPair pair3;
  byte buffer[pair1.getByteSize()];
  pair1.serialize(buffer, pair1.getByteSize());
  printf("serialization successful \n");
  pair3.deserialize(buffer);
  assert(pair1.equals(&pair3));
  assert(!pair2.equals(&pair3));
  assert(!pair4.equals(&pair3));
  printf("deserialization successful \n");
}

void testSigner()
{
  printf("\n \n Testing the Signer class \n");
  srand(0);
  uint8_t seed1[32];
  uint8_t seed2[32];
  getRandomSeed(seed1, sizeof(seed1), rand());
  getRandomSeed(seed2, sizeof(seed2), rand());

  Signer signer(seed1, sizeof(seed1));
  Signer signer2(seed2, sizeof(seed2));

  bloom_filter* filter1 = new bloom_filter(BF_N, BF_P, BF_SEED);
  bloom_filter* filter2 = new bloom_filter(BF_N, BF_P, BF_SEED);
  filter1->clear();
  filter2->clear();
  string str1 = "content1";
  string str2 = "content2342112124";
  filter1->insert(str1);
  filter2->insert(str2);

  BloomFilterContainer container = BloomFilterContainer((SignerId)111, *filter1);

  P1 sig1 = signer.sign(filter1->bit_table_, filter1->size() / 8);
  P1 sig1a = signer.sign((byte*)(filter1->table()), filter1->size() / 8);
  P1 sig2 = signer.sign(filter1);
  P1 sig3 = signer.sign(&container);

  P1 sig4 = signer.sign(filter2);
  P1 sig5 = signer2.sign(filter1);
  P1 sig6 = signer2.sign(filter2);

  P1_Affine* affine_signature1 = new P1_Affine(sig1);
  P1_Affine* affine_signature2 = new P1_Affine(sig2);
  P1_Affine* affine_signature6 = new P1_Affine(sig6);

  assert(affine_signature1->in_group() == 1);
  assert(affine_signature2->in_group() == 1);

  assert(affine_signature1->core_verify(signer.getPublicKey(), 1, filter1->bit_table_, filter1->size() / 8) == BLST_SUCCESS);
  assert(affine_signature2->core_verify(signer.getPublicKey(), 1, filter1->bit_table_, filter1->size() / 8) == BLST_SUCCESS);

  assert(sig1.is_equal(sig1a));
  assert(sig1.is_equal(sig2));
  assert(sig2.is_equal(sig3));

  assert(!sig1.is_equal(sig4));
  assert(!sig1.is_equal(sig5));

  vector<SignedMessage> messages;
  SignedMessage m1 = SignedMessage(filter1, &signer.getPublicKey());
  SignedMessage m2 = SignedMessage(filter2, &signer2.getPublicKey());
  messages.push_back(m1);
  messages.push_back(m2);

  vector<P1_Affine> signatures;
  signatures.push_back(*affine_signature1);
  signatures.push_back(*affine_signature6);

  assert(Signer::verify(messages, signatures));

#pragma region signature_logging
  // byte sigser[96];
  // sig1->serialize(sigser);
  // uint32_t *longg = (uint32_t *)sigser;
  // printf("signature: ");
  // for (int i=0; i< 24; i++)
  //   printf("%u", *(longg + i));
  // printf("\n");

  // sig2->serialize(sigser);
  // longg = (uint32_t *)sigser;
  // printf("signature: ");
  // for (int i=0; i< 24; i++)
  //   printf("%u", *(longg + i));
  // printf("\n");


  // sig3->serialize(sigser);
  // longg = (uint32_t *)sigser;
  // printf("signature: ");
  // for (int i=0; i< 24; i++)
  //   printf("%u", *(longg + i));
  // printf("\n");
#pragma endregion
}

void testSignerWithReductions()
{
  printf("\n \n Testing the Signer class on BfContainer with reduction \n");
  srand(0);
  uint8_t seed1[32];
  uint8_t seed2[32];
  getRandomSeed(seed1, sizeof(seed1), rand());
  getRandomSeed(seed2, sizeof(seed2), rand());

  Signer signer(seed1, sizeof(seed1));
  Signer signer2(seed2, sizeof(seed2));

  bloom_filter* filter1 = new bloom_filter(BF_N, BF_P, BF_SEED);
  bloom_filter* filter2 = new bloom_filter(BF_N, BF_P, BF_SEED);
  filter1->clear();
  filter2->clear();
  string str1 = "content1";
  string str2 = "content2342112124";
  filter1->insert(str1);
  filter2->insert(str2);

  BloomFilterContainer container = BloomFilterContainer((SignerId)111, *filter1);

  P1 sig1 = signer.sign(&container);
  P1_Affine* affine_signature1 = new P1_Affine(sig1);
  assert(affine_signature1->in_group() == 1);
  assert(affine_signature1->core_verify(signer.getPublicKey(), 1, filter1->table(), filter1->size() / 8) == BLST_SUCCESS);

  container.addReduction(filter2, (SignerId)222);
  P1 sig2 = signer.sign(&container);
  P1_Affine* affine_signature2 = new P1_Affine(sig2);
  assert(affine_signature2->in_group() == 1);
  assert(affine_signature1->is_equal(*affine_signature2) == 0);

  vector<SignedMessage> messages;
  SignedMessage m1 = SignedMessage(filter1, &signer.getPublicKey());
  SignedMessage m2 = SignedMessage(filter2, &signer.getPublicKey());
  messages.push_back(m1);
  messages.push_back(m2);

  vector<P1_Affine> signatures;
  signatures.push_back(*affine_signature2);

  vector<P1_Affine> signatures2;
  signatures2.push_back(*affine_signature1);

  assert(Signer::verify(messages, signatures) == 1);
  assert(Signer::verify(messages, signatures2) == 0);

  // assert(affine_signature2->in_group() == 1);
  // assert(affine_signature2->core_verify(signer.getPublicKey(), 1, filter1->bit_table_, filter1->size() / 8) == BLST_SUCCESS);


  // vector<SignedMessage> messages;
  // SignedMessage m1 = SignedMessage(filter1, &signer.getPublicKey());
  // SignedMessage m2 = SignedMessage(filter2, &signer2.getPublicKey());
  // messages.push_back(m1);
  // messages.push_back(m2);

  // vector<P1_Affine> signatures;
  // signatures.push_back(*affine_signature1);
  // signatures.push_back(*affine_signature6);

  // assert(Signer::verify(messages, signatures));
}

void testSignedSerializedData()
{
  printf("\n \n testing serialized signed data \n");
#pragma region Setup
  srand(0);
  uint8_t seed1[32];
  uint8_t seed2[32];
  uint8_t seed3[32];
  getRandomSeed(seed1, sizeof(seed1), rand());
  getRandomSeed(seed2, sizeof(seed2), rand());
  getRandomSeed(seed3, sizeof(seed3), rand());

  Signer signer1(seed1, sizeof(seed1));
  Signer signer2(seed2, sizeof(seed2));
  Signer signer3(seed3, sizeof(seed3));

  BloomFilterContainer serialized = BloomFilterContainer((SignerId)111);
  BloomFilterContainer container2 = BloomFilterContainer((SignerId)222);
  BloomFilterContainer container3 = BloomFilterContainer((SignerId)333);

  bloom_filter *m_bloomFilter = new bloom_filter(BF_N, BF_P, BF_SEED);
  m_bloomFilter->insert("content487877951");
  BloomFilterContainer container2b = BloomFilterContainer((SignerId)222);
  container2b.getBloomFilter()->insert("content487877951");
  assert(m_bloomFilter->contains("content487877951"));
  assert(container2b.getBloomFilter()->contains("content487877951"));

  
  printf("reducing and serializing following: \n");
  serialized.getBloomFilter()->insert("content1");
  serialized.getBloomFilter()->insert("hello hello hello");
  container2.getBloomFilter()->insert("content487877951");
  container3.getBloomFilter()->insert("some other string which hashes different");

  serialized.printFilter();
  container2.printFilter();
  container3.printFilter();

  assert(container2.getBloomFilter()->contains("content487877951"));
  assert(container2.getBloomFilter()->contains("content487877951"));

  // ensure we are not testing with same filters
  assert(!(*(serialized.getBloomFilter()) == *(container2.getBloomFilter())));
  assert(!(*(container2.getBloomFilter()) == *(container3.getBloomFilter())));
  assert(!(*(serialized.getBloomFilter()) == *(container3.getBloomFilter())));

  P1 sig1 = signer1.sign(&serialized);
  P1_Affine* affine_signature1 = new P1_Affine(sig1);
  P1 sig2 = signer2.sign(&container2);
  P1_Affine* affine_signature2 = new P1_Affine(sig2);
  P1 sig3 = signer3.sign(&container3);
  P1_Affine* affine_signature3 = new P1_Affine(sig3);

  // check the validity of single signatures

  assert(Signer::verify((byte*)serialized.getBloomFilter()->table(), serialized.getBloomFilter()->size() / 8, affine_signature1, signer1.getPublicKey()));
  assert(affine_signature1->core_verify(signer1.getPublicKey(), 1, serialized.getBloomFilter()->table(), serialized.getBloomFilter()->size() / 8) == BLST_SUCCESS);
  assert(affine_signature2->core_verify(signer2.getPublicKey(), 1, container2.getBloomFilter()->table(), container2.getBloomFilter()->size() / 8) == BLST_SUCCESS);
  assert(affine_signature3->core_verify(signer3.getPublicKey(), 1, container3.getBloomFilter()->table(), container3.getBloomFilter()->size() / 8) == BLST_SUCCESS);


  // TODO create: addReduction(BloomFilterContainer container)
  serialized.addReduction(container2.getBloomFilter(), container2.getSignerId());
  serialized.addReduction(container3.getBloomFilter(), container3.getSignerId());
#pragma endregion

  unsigned char buffer[serialized.getByteSize()];
  serialized.serialize(buffer, serialized.getByteSize());

  BloomFilterContainer deserialized;
  deserialized.deserialize(buffer);

  assert(serialized.equals(&deserialized));
  assert(affine_signature1->core_verify(signer1.getPublicKey(), 1, deserialized.getBloomFilter()->table(), deserialized.getBloomFilter()->size() / 8) == BLST_SUCCESS);

  std::vector<BloomFilterContainer*> reconstructed = deserialized.reconstructBfs();

  printf("deserialized and reconstructed following: \n");
  deserialized.printFilter();
  for (size_t i = 0; i < reconstructed.size(); i++) {
    BloomFilterContainer* container = reconstructed[i];
    container->printFilter();
    // this is the quickest way to do it, I guess
    if (container->getSignerId() == (SignerId)222) {
      assert(Signer::verify(container->getBloomFilter()->bit_table_, container->getBloomFilter()->size() / 8, affine_signature2, signer2.getPublicKey()));
      assert(affine_signature2->core_verify(signer2.getPublicKey(), 1, container->getBloomFilter()->table(), container->getBloomFilter()->size() / 8) == BLST_SUCCESS);
      assert(container->getBloomFilter()->contains("content487877951"));
    }
    else {
      assert(Signer::verify(container->getBloomFilter()->bit_table_, container->getBloomFilter()->size() / 8, affine_signature3, signer3.getPublicKey()));
      assert(affine_signature3->core_verify(signer3.getPublicKey(), 1, container->getBloomFilter()->table(), container->getBloomFilter()->size() / 8) == BLST_SUCCESS);
      assert(container->getBloomFilter()->contains("some other string which hashes different"));
    }
  }
}

void testInterests()
{
#pragma region init_bloomFilters
  BloomFilterContainer containerTwoReductions = BloomFilterContainer((SignerId)111);
  BloomFilterContainer containerOneReduction = BloomFilterContainer((SignerId)222);
  BloomFilterContainer containerNoReductions = BloomFilterContainer((SignerId)666);
  BloomFilterContainer container3 = BloomFilterContainer((SignerId)333);
  BloomFilterContainer container4 = BloomFilterContainer((SignerId)444);
  BloomFilterContainer container5 = BloomFilterContainer((SignerId)555);
  printf("\n \n Testing of BlsInterest \n");
  printf("reducing and serializing following: \n");
  containerTwoReductions.getBloomFilter()->insert("content1");
  containerTwoReductions.getBloomFilter()->insert("hello hello hello");
  containerOneReduction.getBloomFilter()->insert("content487877951");
  container3.getBloomFilter()->insert("some other string which hashes different");
  container4.getBloomFilter()->insert("some other string which hashes different!!");
  container5.getBloomFilter()->insert("some other string which hashes kasdfk");
  containerNoReductions.getBloomFilter()->insert("42");

  containerTwoReductions.printFilter();
  containerOneReduction.printFilter();
  container3.printFilter();
  container4.printFilter();
  container5.printFilter();
  containerNoReductions.printFilter();

  // ensure we are not testing with same filters
  assert(!(*(containerTwoReductions.getBloomFilter()) == *(containerOneReduction.getBloomFilter())));
  assert(!(*(containerOneReduction.getBloomFilter()) == *(container3.getBloomFilter())));
  assert(!(*(containerTwoReductions.getBloomFilter()) == *(container3.getBloomFilter())));

  containerTwoReductions.addReduction(container3.getBloomFilter(), container3.getSignerId());
  containerTwoReductions.addReduction(container4.getBloomFilter(), container4.getSignerId());
  containerOneReduction.addReduction(container5.getBloomFilter(), container5.getSignerId());

  assert(containerOneReduction.getReductions().size() == 1);
  assert(containerTwoReductions.getReductions().size() == 2);
  assert(containerNoReductions.getReductions().size() == 0);

  srand(0);
  uint8_t seed1[32];
  uint8_t seed2[32];
  getRandomSeed(seed1, sizeof(seed1), rand());
  getRandomSeed(seed2, sizeof(seed2), rand());

  Signer signer1(seed1, sizeof(seed1));
  Signer signer2(seed2, sizeof(seed2));
  Signer signer3(seed1, sizeof(seed1));

#pragma endregion
  // P1 sig1 = signer1.sign(&containerTwoReductions);
  // P1_Affine* affineSig1 = new P1_Affine(sig1);
  P1_Affine affineSig1 = signer1.sign(&containerTwoReductions).to_affine();
  BlsInterest* interest1 = new BlsInterest(BlsInterest::CAR, &affineSig1);
  interest1->_addBloomFilter(&containerTwoReductions);
  interest1->_addSigner(new SidPkPair(containerTwoReductions.getSignerId(), signer1.getPublicKey()));
  interest1->_addSigner(new SidPkPair(container3.getSignerId(), signer1.getPublicKey()));
  interest1->_addSigner(new SidPkPair(container4.getSignerId(), signer1.getPublicKey()));

  assert(interest1->_verify());
  assert(interest1->_getBloomFilters().size() == 1);

  P1_Affine affineSig2 = signer2.sign(&containerOneReduction).to_affine();
  BlsInterest* interest2 = new BlsInterest(BlsInterest::CAR, &affineSig2);
  interest2->_addBloomFilter(&containerOneReduction);
  interest2->_addSigner(new SidPkPair(containerOneReduction.getSignerId(), signer2.getPublicKey()));
  interest2->_addSigner(new SidPkPair(container5.getSignerId(), signer2.getPublicKey()));
  assert(interest2->_getBloomFilters().size() == 1);
  assert(interest2->_verify());

  P1_Affine affineSig3 = signer3.sign(&containerNoReductions).to_affine();
  BlsInterest* interest3 = new BlsInterest(BlsInterest::CAR, &affineSig3);
  interest3->_addBloomFilter(&containerNoReductions);
  interest3->_addSigner(new SidPkPair(containerNoReductions.getSignerId(), signer3.getPublicKey()));
  assert(interest3->_getBloomFilters().size() == 1);
  assert(interest3->_verify());

  // merging of two interest with reductions means preserving both of the bf containers
  interest1->_merge(interest2);
  assert(interest1->_verify());
  assert(interest1->_getBloomFilters().size() == 2);

  // merging of two interest one of which has no reductions means we can reduce the second bf container
  interest1->_merge(interest3);
  assert(interest1->_verify());
  assert(interest1->_getBloomFilters().size() == 2);
}

int main(int argc, char* argv[])
{
  // Test signatures
  testEncryption();

  // Test BfXorRepresentation
  testBfReductions();

  // Test BfXorRepresentation serialization + deserialization
  testBfReductionSerDeser();


  // Test BloomFilterContainer
  testBfContainer();


  // Test BfContainer serialize + deserialize
  testBfContainerSerDeser();

  // Test SidPkPair with serialization
  testSidPkPair();

  // 
  testSigner();

  // testSignerWithReductions
  testSignerWithReductions();

  //
  testSignedSerializedData();

  //
  testInterests();

  printf("Size of bloom filters is set to: %i and DELTA_MAX is %i \n", BF_M, DELTA_MAX);

#pragma region Bit stuff
  // unsigned char c0 = (1 << 0);
  // unsigned char c2 = (1 << 2);
  // unsigned char c4 = (1 << 4);
  // unsigned char c5 = (1 << 5);
  // unsigned char c7 = (1 << 7);

  // printByte(c0);
  // printf("\n %hu \n", c0);
  // printByte(c2);
  // printf("\n %hu \n", c2);
  // printByte(c4);
  // printf("\n %hu \n", c4);
  // printByte(c5);
  // printf("\n %hu \n", c5);
  // printByte(c7);
  // printf("\n %hu \n", c7);
#pragma endregion

  printf("done \n");

  Simulator::Run();
  Simulator::Destroy();
  return 0;
}
