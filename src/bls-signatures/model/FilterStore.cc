#include "ns3/FilterStore.hpp"

namespace ns3 {
        FilterStore::FilterStore() {
        filters.clear();
        faces.clear();
    }

    FilterStore::~FilterStore() {
        printf("destructing filterStore \n");
        faces.clear();
        for (size_t i = 0; i < filters.size(); i++) {
            delete filters.at(i);
        }
        filters.clear();
    }

    // vector<bloom_filter*> FilterStore::getFilters() {
    //     return filters;
    // }

    // vector<int> FilterStore::getFaces() {
    //     return faces;
    // }

    size_t FilterStore::getSize() {
        if (filters.size() != faces.size()) {
            printf("ERROR in FilterStore: faces and filters have different size");
            return 0;
        }

        return filters.size();
    }

    pair<bloom_filter*, int> FilterStore::getFilterPair(size_t index) {
        if (index < filters.size()) {
            return pair<bloom_filter*, int>(filters[index], faces[index]);
        }
        printf("ERROR in FilterStore: out of bounds access");
        return make_pair<bloom_filter*, int>(NULL, 0);
    }

    size_t FilterStore::insertFilterPair(bloom_filter* filter, int faceId) {
        bloom_filter* newFilter = new bloom_filter(*filter);
        filters.push_back(newFilter);
        faces.push_back(faceId);

        return filters.size() - 1;
    }

    size_t FilterStore::insertFilterPair(bloom_filter filter, int faceId) {
        bloom_filter* newFilter = new bloom_filter(filter);
        filters.push_back(newFilter);
        faces.push_back(faceId);

        return filters.size() - 1;
    }

    void FilterStore::deleteEntry(size_t index) {
        if (index >= getSize()) return;

        auto face_to_remove = faces.begin() + index;
        if (face_to_remove != faces.end()) {
            faces.erase(face_to_remove);
        }

        auto filter_to_remove = filters.begin() + index;
        if (filter_to_remove != filters.end()) {
            delete filters[index];
            filters.erase(filter_to_remove);
        }
    }
}