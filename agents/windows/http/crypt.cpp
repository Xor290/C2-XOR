#include "crypt.h"

std::string xor_data(const std::string &data, const std::string &key) {
    std::string out = data;
    size_t klen = key.length();
    for (size_t i = 0; i < out.size(); ++i)
        out[i] ^= key[i % klen];
    return out;
}
