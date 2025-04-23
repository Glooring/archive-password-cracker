#pragma once

#include <vector>
#include <string>
#include <cstdint> // For uint64_t, uint32_t
#include <cmath>   // For std::log, std::ceil
#include <fstream> // For file I/O
#include <stdexcept> // For exceptions
#include <limits>  // For numeric_limits

// Simple FNV-1a 64-bit hash function
inline uint64_t fnv1a_hash(const void* key, int len) {
    uint64_t hash = 0xcbf29ce484222325ULL; // FNV offset basis
    const unsigned char* p = static_cast<const unsigned char*>(key);
    for (int i = 0; i < len; ++i) {
        hash ^= static_cast<uint64_t>(p[i]);
        hash *= 0x100000001b3ULL; // FNV prime
    }
    return hash;
}

extern std::string skipListFilePath;

class BloomFilter {
public:
    // Constructor: Calculates optimal size and hash count
    BloomFilter(uint64_t estimated_items, double false_positive_rate);

    // Default constructor for deserialization
    BloomFilter() : m_num_bits(0), m_num_hashes(0), m_estimated_items(0), m_fp_rate(0.0) {}

    // Add an item to the filter
    void insert(const std::string& item);

    // Check if an item might be in the filter
    bool contains(const std::string& item) const;

    // Serialize the filter state to a file
    bool serialize(const std::string& filepath) const;

    // Deserialize the filter state from a file
    bool deserialize(const std::string& filepath);

    // Getters (optional)
    uint64_t getNumBits() const { return m_num_bits; }
    uint32_t getNumHashes() const { return m_num_hashes; }
    bool isValid() const { return !m_bits.empty() && m_num_hashes > 0; }

private:
    uint64_t m_num_bits;        // Size of the bit vector (m)
    uint32_t m_num_hashes;      // Number of hash functions (k)
    uint64_t m_estimated_items; // Expected number of items (n) - stored for info
    double m_fp_rate;           // Target false positive rate (p) - stored for info
    std::vector<bool> m_bits;   // The bit vector

    // Generate k hash values for an item
    void generate_hashes(const std::string& item, std::vector<uint64_t>& hashes) const;
};