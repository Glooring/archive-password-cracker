#include "bloom_filter.h"
#include <iostream> // For error messages during serialization/deserialization

// Magic number and version for file format
const uint32_t BLOOM_FILTER_MAGIC = 0xBF10F17E;
const uint16_t BLOOM_FILTER_VERSION = 1;

BloomFilter::BloomFilter(uint64_t estimated_items, double false_positive_rate)
    : m_estimated_items(estimated_items), m_fp_rate(false_positive_rate)
{
    if (estimated_items == 0 || false_positive_rate <= 0.0 || false_positive_rate >= 1.0) {
         // Handle invalid parameters, maybe default or throw?
         // For now, create a minimal valid filter to avoid crashes downstream
         m_num_bits = 8; // Minimal size
         m_num_hashes = 1; // Minimal hashes
         m_bits.resize(m_num_bits, false);
         std::cerr << "[WARN] BloomFilter: Invalid parameters, using minimal default." << std::endl;
         return;
    }

    // Calculate optimal size (m) and hash count (k)
    // m = - (n * ln(p)) / (ln(2)^2)
    double m_exact = - (static_cast<double>(estimated_items) * std::log(false_positive_rate)) / (std::log(2.0) * std::log(2.0));
    // k = (m / n) * ln(2)
    double k_exact = (m_exact / static_cast<double>(estimated_items)) * std::log(2.0);

    m_num_bits = static_cast<uint64_t>(std::ceil(m_exact));
    // Ensure minimum size and reasonable upper bound if needed
    if (m_num_bits < 8) m_num_bits = 8;
    // Add a safety check for extremely large sizes if memory is a concern
    // uint64_t max_bits = 4ULL * 1024 * 1024 * 1024 * 8; // e.g., 4GB limit
    // if (m_num_bits > max_bits) { /* Handle error: too large */ }

    m_num_hashes = static_cast<uint32_t>(std::ceil(k_exact));
    if (m_num_hashes < 1) m_num_hashes = 1;
    if (m_num_hashes > 20) m_num_hashes = 20; // Practical upper limit?

    try {
        m_bits.resize(m_num_bits, false);
    } catch (const std::bad_alloc& e) {
        std::cerr << "[ERROR] BloomFilter: Failed to allocate " << m_num_bits << " bits." << std::endl;
        // Make filter invalid
        m_num_bits = 0;
        m_num_hashes = 0;
        m_bits.clear();
        // Rethrow or handle as appropriate for the application
        throw;
    }
}

void BloomFilter::generate_hashes(const std::string& item, std::vector<uint64_t>& hashes) const {
    hashes.resize(m_num_hashes);
    // Use double hashing technique: H(i) = (h1(item) + i * h2(item)) mod m
    uint64_t h1 = fnv1a_hash(item.c_str(), item.length());
    // Use a different seed/basis for the second hash
    uint64_t h2 = fnv1a_hash(&h1, sizeof(h1)); // Hash the first hash for simplicity

    for (uint32_t i = 0; i < m_num_hashes; ++i) {
        hashes[i] = (h1 + i * h2) % m_num_bits;
    }
}

void BloomFilter::insert(const std::string& item) {
    if (!isValid()) return; // Don't operate on an invalid filter
    std::vector<uint64_t> hashes;
    generate_hashes(item, hashes);
    for (uint64_t hash_index : hashes) {
        m_bits[hash_index] = true;
    }
}

bool BloomFilter::contains(const std::string& item) const {
    if (!isValid()) return false; // Treat invalid filter as containing nothing
    std::vector<uint64_t> hashes;
    generate_hashes(item, hashes);
    for (uint64_t hash_index : hashes) {
        if (!m_bits[hash_index]) {
            return false; // Definitely not present
        }
    }
    return true; // Probably present (or false positive)
}

bool BloomFilter::serialize(const std::string& filepath) const {
    if (!isValid()) return false;
    std::ofstream ofs(filepath, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        std::cerr << "[ERROR] BloomFilter: Cannot open file for writing: " << filepath << std::endl;
        return false;
    }

    // Write header: magic, version, num_bits, num_hashes, estimated_items, fp_rate
    ofs.write(reinterpret_cast<const char*>(&BLOOM_FILTER_MAGIC), sizeof(BLOOM_FILTER_MAGIC));
    ofs.write(reinterpret_cast<const char*>(&BLOOM_FILTER_VERSION), sizeof(BLOOM_FILTER_VERSION));
    ofs.write(reinterpret_cast<const char*>(&m_num_bits), sizeof(m_num_bits));
    ofs.write(reinterpret_cast<const char*>(&m_num_hashes), sizeof(m_num_hashes));
    ofs.write(reinterpret_cast<const char*>(&m_estimated_items), sizeof(m_estimated_items));
    ofs.write(reinterpret_cast<const char*>(&m_fp_rate), sizeof(m_fp_rate));

    // Write bit vector (packed)
    uint64_t num_bytes = (m_num_bits + 7) / 8;
    std::vector<uint8_t> packed_bits(num_bytes, 0);
    for (uint64_t i = 0; i < m_num_bits; ++i) {
        if (m_bits[i]) {
            packed_bits[i / 8] |= (1 << (i % 8));
        }
    }
    ofs.write(reinterpret_cast<const char*>(packed_bits.data()), num_bytes);

    return ofs.good();
}

bool BloomFilter::deserialize(const std::string& filepath) {
    std::ifstream ifs(filepath, std::ios::binary);
    if (!ifs) {
        // File doesn't exist or cannot be opened - this is not necessarily an error
        // std::cerr << "[INFO] BloomFilter: Skip file not found or cannot open: " << filepath << std::endl;
        return false;
    }

    uint32_t magic = 0;
    uint16_t version = 0;

    // Read and validate header
    ifs.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if (!ifs || magic != BLOOM_FILTER_MAGIC) {
        std::cerr << "[WARN] BloomFilter: Invalid magic number in file: " << filepath << std::endl;
        return false;
    }
    ifs.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (!ifs || version != BLOOM_FILTER_VERSION) {
         std::cerr << "[WARN] BloomFilter: Incompatible version in file: " << filepath << std::endl;
        return false;
    }

    // Read parameters
    ifs.read(reinterpret_cast<char*>(&m_num_bits), sizeof(m_num_bits));
    ifs.read(reinterpret_cast<char*>(&m_num_hashes), sizeof(m_num_hashes));
    ifs.read(reinterpret_cast<char*>(&m_estimated_items), sizeof(m_estimated_items));
    ifs.read(reinterpret_cast<char*>(&m_fp_rate), sizeof(m_fp_rate));

    if (!ifs || m_num_bits == 0 || m_num_hashes == 0) {
         std::cerr << "[WARN] BloomFilter: Invalid parameters read from file: " << filepath << std::endl;
         m_num_bits = 0; m_num_hashes = 0; // Invalidate filter
         return false;
    }

    // Read bit vector (packed)
    uint64_t num_bytes = (m_num_bits + 7) / 8;
    std::vector<uint8_t> packed_bits(num_bytes);
    ifs.read(reinterpret_cast<char*>(packed_bits.data()), num_bytes);

    if (!ifs || ifs.peek() != EOF) { // Check if read failed or if there's extra data
        std::cerr << "[WARN] BloomFilter: Error reading bit vector or extra data found in file: " << filepath << std::endl;
        m_num_bits = 0; m_num_hashes = 0; // Invalidate filter
        return false;
    }

    // Unpack bits
    try {
        m_bits.resize(m_num_bits);
        for (uint64_t i = 0; i < m_num_bits; ++i) {
            m_bits[i] = (packed_bits[i / 8] >> (i % 8)) & 1;
        }
    } catch (const std::exception& e) {
         std::cerr << "[ERROR] BloomFilter: Error unpacking bits from file: " << filepath << " (" << e.what() << ")" << std::endl;
         m_num_bits = 0; m_num_hashes = 0; m_bits.clear(); // Invalidate filter
         return false;
    }

    return true; // Deserialization successful
}