#ifndef FILTER_STORE_H
#define FILTER_STORE_H

#include "ns3/bloom_filter.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <array>
#include <vector>

using namespace std;

namespace ns3 {
    class FilterStore {
    private:
        vector<bloom_filter*> filters;
        vector<int> faces;

    public:
        FilterStore();
        ~FilterStore();
        // these should probably not be accessible
        // vector<bloom_filter*> getFilters();
        // vector<int> getFaces();

        pair<bloom_filter*, int> getFilterPair(size_t index);
        size_t insertFilterPair(bloom_filter* filter, int faceId);
        size_t insertFilterPair(bloom_filter filter, int faceId);
        void deleteEntry(size_t index);
    
        size_t getSize();
    };
}

#endif