#pragma once

#include <string>
#include <atomic>
#include <mutex>
#include <thread>
#include <vector>
#include <cstdint> // For uint64_t
#include <map>

// Forward declaration for BloomFilter
class BloomFilter;

// Enum to represent the cracking order/mode
enum class CrackingMode {
    ASCENDING,
    DESCENDING,
    RANDOM_LCG // Internally uses shuffled indices
};

// Function to output status messages (defined in main.cpp)
extern void update_output(const std::string& message);

// Main brute-force function signature updated to include filter parameters
std::string brute_force_worker_combined(
    const std::string& charset,
    int min_length,
    int max_length,
    const std::string& archivePath,
    CrackingMode mode,
    BloomFilter* filter,
    std::mutex* filterMutex,
    int checkpointInterval,
    const std::string& pattern = ""  // Optional pattern for wildcard matching
);

void generate_suffix_combinations(
    const std::string& charset,
    std::string& suffix,
    size_t idx,
    const std::string& current_pwd,
    size_t segment_idx,
    int pos,
    int length,
    const std::vector<std::string>& segments,
    std::atomic<bool>& foundFlag,
    std::string& foundPassword_out,
    std::mutex& foundMutex,
    BloomFilter* filter,
    std::mutex* filterMutex,
    const std::string& archivePath,
    const std::string& stop_flag_path,
    std::atomic<bool>& stop_requested);

// External variable for the 7z path (defined in main.cpp)
extern std::string sevenZipPath;

// Helper function to convert a GLOBAL index (starting from length 1) to a password string.
// No change needed here, the caller (random mode) will adjust the index.
bool getPasswordByIndex(uint64_t index, const std::string& charset, int max_length, std::string& out_password);

// --- NEW Declaration ---
// Translates a global index (across all valid pattern lengths) to a password
bool getPatternPasswordByGlobalIndex(
    uint64_t global_pattern_index, // Index within the total pattern space
    const std::vector<std::string>& segments,
    const std::string& charset,
    int min_len,
    int max_len,
    const std::map<int, uint64_t>& per_length_counts, // Pre-calculated counts per length
    std::string& out_password
);
// --- END NEW ---