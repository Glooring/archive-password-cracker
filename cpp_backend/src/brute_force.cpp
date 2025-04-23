// --- FIX: Define NOMINMAX before including potentially conflicting headers ---
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif
// --- End FIX ---

#include "brute_force.h"  // Includes CrackingMode enum, function declarations
#include "bloom_filter.h" // Include Bloom Filter header
#include <iostream>       // For std::cout, std::cerr
#include <sstream>        // For std::ostringstream
#include <vector>         // For std::vector
#include <algorithm>      // For std::shuffle, std::min
#include <cmath>          // For std::log, std::ceil
#include <limits>         // For std::numeric_limits
#include <chrono>         // For timing (std::chrono) AND SEEDING
#include <cstdio>         // For C-style file I/O (popen etc)
#include <numeric>        // For std::iota (filling index vector)
#include <stdexcept>      // For exceptions like std::bad_alloc, std::overflow_error
#include <random>         // For std::mt19937_64, std::shuffle, std::random_device
#include <thread>         // For std::thread, std::hardware_concurrency
#include <mutex>          // For std::mutex, std::lock_guard
#include <atomic>         // For std::atomic<bool>
#include <iomanip>        // For std::fixed, std::setprecision in RAM log message
#include <fstream>
#include <optional> // For std::optional
#include <map>      // For std::map in random pattern mode

// Platform-specific includes for process management
#ifdef _WIN32
#include <windows.h>  // For CreateProcessW, WaitForSingleObject, etc.
#else                 // Linux/macOS
#include <sys/wait.h> // For waitpid
#include <unistd.h>   // For fork, execvp, access, open, dup2, close
#include <cstdlib>    // For exit
#include <cstring>    // For C-style string functions if needed
#include <fcntl.h>    // For open flags (O_WRONLY)
#endif

typedef unsigned long long uint64;

// External variables defined in main.cpp
extern std::string skipListFilePath;                   // Use the path directly for saving
extern std::string sevenZipPath;                       // Defined in main.cpp
extern void update_output(const std::string &message); // Defined in main.cpp

struct PatternInfo
{
    int fixed_length; // Sum of literal lengths + number of '?'
    int num_stars;    // Number of '*' wildcards
};

// ================================================================
// ===                UTILITY / HELPER FUNCTIONS                ===
// ================================================================

// --- Pattern Parsing and Info ---
std::vector<std::string> parse_pattern(const std::string &pattern)
{
    std::vector<std::string> segments;
    std::string current_segment;
    bool escape = false;

    for (char c : pattern)
    {
        if (escape)
        {
            current_segment += c;
            escape = false;
        }
        else if (c == '\\')
        {
            escape = true;
        }
        else if (c == '*' || c == '?')
        {
            if (!current_segment.empty())
            {
                segments.push_back(current_segment);
                current_segment.clear();
            }
            segments.push_back(std::string(1, c));
        }
        else
        {
            current_segment += c;
        }
    }
    if (!current_segment.empty())
    {
        segments.push_back(current_segment);
    }
    return segments;
}

PatternInfo calculate_pattern_info(const std::vector<std::string> &segments)
{
    int fixed_length = 0;
    int num_stars = 0;
    for (const auto &segment : segments)
    {
        if (segment == "*")
        {
            num_stars++;
        }
        else if (segment == "?")
        {
            fixed_length++;
        }
        else
        {
            fixed_length += segment.length();
        }
    }
    return {fixed_length, num_stars};
}

// --- Calculates combinations for a pattern at a specific length ---
std::optional<uint64_t> calculate_pattern_combinations(
    const std::vector<std::string> &segments,
    uint64_t charset_size,
    int total_length)
{
    if (charset_size == 0)
        return 0;

    PatternInfo info = calculate_pattern_info(segments);
    int fixed_part_len_total = info.fixed_length;
    int num_stars = info.num_stars;
    int num_qmarks = 0;

    for (const auto &seg : segments)
    {
        if (seg == "?")
            num_qmarks++;
    }

    if (total_length < fixed_part_len_total)
        return 0;

    if (num_stars == 0)
    {
        if (total_length != fixed_part_len_total)
            return 0;
        int wildcard_chars = num_qmarks;
        if (wildcard_chars == 0)
            return 1;
        uint64_t combinations = 1;
        for (int i = 0; i < wildcard_chars; ++i)
        {
            if (combinations > std::numeric_limits<uint64>::max() / charset_size)
                return std::nullopt;
            combinations *= charset_size;
        }
        return combinations;
    }
    else if (num_stars == 1)
    {
        int star_chars = total_length - fixed_part_len_total;
        if (star_chars < 0)
            return 0;
        int total_wildcard_chars = num_qmarks + star_chars;
        if (total_wildcard_chars == 0)
            return 1;
        uint64_t combinations = 1;
        for (int i = 0; i < total_wildcard_chars; ++i)
        {
            if (combinations > std::numeric_limits<uint64>::max() / charset_size)
                return std::nullopt;
            combinations *= charset_size;
        }
        return combinations;
    }
    else
    {
        return std::nullopt; // Multiple stars: too complex for this calculation
    }
}

// --- Check if stop flag file exists ---
static bool stop_flag_exists(const std::string &path)
{
    std::ifstream flag_file(path);
    return flag_file.good();
}

// --- Tries a single password against the archive ---
static bool tryPassword(const std::string &password, const std::string &archivePath)
{
    if (sevenZipPath.empty())
    {
        update_output("ERROR: tryPassword called but 7z path is empty.");
        return false;
    }
#ifdef _WIN32
    std::wstring wSevenZipPath, wArchivePath, wPasswordArg;
    try
    {
        auto to_wstring = [](const std::string &utf8_str) -> std::wstring
        {
            if (utf8_str.empty())
                return L"";
            int len = MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), -1, NULL, 0);
            if (len == 0)
                throw std::runtime_error("MB2WC len=0 err: " + std::to_string(GetLastError()));
            std::vector<wchar_t> buf(len);
            if (MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(), -1, buf.data(), len) == 0)
                throw std::runtime_error("MB2WC conv err: " + std::to_string(GetLastError()));
            return buf.data();
        };
        wSevenZipPath = to_wstring(sevenZipPath);
        wArchivePath = to_wstring(archivePath);
        wPasswordArg = to_wstring("-p" + password);
    }
    catch (const std::exception &e)
    {
        update_output("ERROR: UTF-8 to WString conversion failed: " + std::string(e.what()) + " - PWD: " + password);
        return false;
    }
    std::wostringstream woss;
    woss << L"\"" << wSevenZipPath << L"\" t \"" << wArchivePath << L"\" " << wPasswordArg << L" -y";
    std::wstring wCmd = woss.str();
    std::vector<wchar_t> cmdLineBuf(wCmd.begin(), wCmd.end());
    cmdLineBuf.push_back(0);
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));
    BOOL success = CreateProcessW(nullptr, cmdLineBuf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!success)
    {
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (exitCode == 0);
#else
    pid_t pid = fork();
    if (pid == -1)
    {
        perror("fork");
        return false;
    }
    if (pid == 0)
    {
        std::string password_arg = "-p" + password;
        const char *argv[] = {sevenZipPath.c_str(), "t", archivePath.c_str(), password_arg.c_str(), "-y", nullptr};
        int devNull = open("/dev/null", O_WRONLY);
        if (devNull != -1)
        {
            dup2(devNull, STDOUT_FILENO);
            dup2(devNull, STDERR_FILENO);
            close(devNull);
        }
        else
        {
            perror("open /dev/null");
        }
        execvp(sevenZipPath.c_str(), const_cast<char *const *>(argv));
        perror("execvp failed");
        exit(127);
    }
    else
    {
        int status;
        waitpid(pid, &status, 0);
        return (WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
#endif
}

// --- Generates password from a standard global index (across all lengths) ---
bool getPasswordByIndex(uint64 index, const std::string &charset, int max_possible_length, std::string &out_password)
{
    uint64 charsetSize = static_cast<uint64>(charset.size());
    if (charsetSize == 0)
        return false;
    uint64 current_index = index;
    uint64 combinations_power = 1;
    for (int len = 1; len <= max_possible_length; ++len)
    {
        uint64 combinations_this_len = 0;
        if (len == 1)
        {
            combinations_this_len = charsetSize;
            combinations_power = charsetSize;
        }
        else
        {
            if (combinations_power > std::numeric_limits<uint64>::max() / charsetSize)
                return false;
            combinations_power *= charsetSize;
            combinations_this_len = combinations_power;
        }
        if (current_index < combinations_this_len)
        {
            out_password.assign(len, charset[0]);
            uint64 index_within_length = current_index;
            for (int i = 0; i < len; ++i)
            {
                uint64 char_idx = index_within_length % charsetSize;
                out_password[len - 1 - i] = charset[char_idx];
                index_within_length /= charsetSize;
                if (index_within_length == 0 && i < len - 1)
                    break;
            }
            return true;
        }
        if (current_index < combinations_this_len)
            return false;
        current_index -= combinations_this_len;
    }
    return false;
}

// --- Generates Nth password matching pattern for a SPECIFIC length ---
// (Must be defined before getPatternPasswordByGlobalIndex)
bool getPatternPasswordByIndex(
    uint64_t index,
    const std::vector<std::string> &segments,
    const std::string &charset,
    int total_length,
    std::string &out_password)
{
    uint64_t charset_size = static_cast<uint64>(charset.size());
    if (charset_size == 0)
        return false;
    int fixed_part_len_literals = 0;
    int num_qmarks = 0;
    int num_stars = 0;
    int star_len = 0;
    for (const auto &seg : segments)
    {
        if (seg == "?")
            num_qmarks++;
        else if (seg == "*")
            num_stars++;
        else
            fixed_part_len_literals += seg.length();
    }
    int fixed_part_len_total = fixed_part_len_literals + num_qmarks;
    if (static_cast<size_t>(total_length) < static_cast<size_t>(fixed_part_len_total))
        return false;
    if (num_stars > 0)
    {
        star_len = total_length - fixed_part_len_total;
        if (star_len < 0)
            return false;
    }
    else
    {
        if (static_cast<size_t>(total_length) != static_cast<size_t>(fixed_part_len_total))
            return false;
    }
    int total_wildcard_chars = num_qmarks + star_len;
    if (total_wildcard_chars < 0)
        return false;
    std::string wildcard_values;
    if (total_wildcard_chars > 0)
    {
        uint64_t combinations_power = 1;
        uint64_t offset = 0;
        for (int len = 1; len < total_wildcard_chars; ++len)
        {
            uint64_t combinations_this_len_offset = 0;
            if (len == 1)
            {
                combinations_this_len_offset = charset_size;
                combinations_power = charset_size;
            }
            else
            {
                if (combinations_power > std::numeric_limits<uint64>::max() / charset_size)
                    return false;
                combinations_power *= charset_size;
                combinations_this_len_offset = combinations_power;
            }
            if (offset > std::numeric_limits<uint64>::max() - combinations_this_len_offset)
                return false;
            offset += combinations_this_len_offset;
        }
        if (offset > std::numeric_limits<uint64>::max() - index)
            return false;
        uint64_t global_index = offset + index;
        if (!getPasswordByIndex(global_index, charset, total_wildcard_chars, wildcard_values))
        {
            update_output("WARN: getPasswordByIndex failed internally...");
            return false;
        }
        if (wildcard_values.length() != static_cast<size_t>(total_wildcard_chars))
        {
            update_output("WARN: Pattern wildcard generation mismatch...");
            return false;
        }
    }
    else
    {
        wildcard_values = "";
    }
    out_password.clear();
    out_password.reserve(total_length);
    int wildcard_idx = 0;
    for (const auto &segment : segments)
    {
        if (segment == "?")
        {
            if (static_cast<size_t>(wildcard_idx) < wildcard_values.length())
            {
                out_password += wildcard_values[wildcard_idx++];
            }
            else
            {
                update_output("ERROR: Pattern assembly mismatch '?'...");
                return false;
            }
        }
        else if (segment == "*")
        {
            int current_star_len = star_len;
            if (static_cast<size_t>(wildcard_idx + current_star_len) <= wildcard_values.length())
            {
                out_password += wildcard_values.substr(wildcard_idx, current_star_len);
                wildcard_idx += current_star_len;
            }
            else
            {
                update_output("ERROR: Pattern assembly mismatch '*'...");
                return false;
            }
        }
        else
        {
            out_password += segment;
        }
    }
    if (out_password.length() != static_cast<size_t>(total_length))
    {
        update_output("ERROR: Final pattern password length mismatch...");
        return false;
    }
    return true;
}

// --- Translates GLOBAL pattern index (across lengths) to a password ---
// (Needs getPatternPasswordByIndex defined above)
bool getPatternPasswordByGlobalIndex(
    uint64_t global_pattern_index,
    const std::vector<std::string> &segments,
    const std::string &charset,
    int min_len,
    int max_len,
    const std::map<int, uint64_t> &per_length_counts,
    std::string &out_password)
{
    uint64_t current_global_index = global_pattern_index;
    for (int L = min_len; L <= max_len; ++L)
    {
        auto it = per_length_counts.find(L);
        if (it != per_length_counts.end())
        {
            uint64_t count_this_length = it->second;
            if (count_this_length == 0)
                continue;
            if (current_global_index < count_this_length)
            {
                uint64_t local_idx = current_global_index;
                // *** Fixed call: Uses the correctly defined function now ***
                return getPatternPasswordByIndex(local_idx, segments, charset, L, out_password);
            }
            else
            {
                if (current_global_index < count_this_length)
                    return false;
                current_global_index -= count_this_length;
            }
        }
    }
    update_output("ERROR: Global pattern index " + std::to_string(global_pattern_index) + " out of range.");
    return false;
}

// ================================================================
// ===                    WORKER THREAD FUNCTIONS               ===
// ================================================================

// --- Worker for sequential mode ---
static void sequential_password_worker(
    int length, uint64 start_idx, uint64 end_idx, const std::string &charset, const std::string &archivePath,
    std::atomic<bool> &foundFlag, std::string &foundPassword_out, std::mutex &foundMutex,
    BloomFilter *filter, std::mutex *filterMutex, const std::string &stop_flag_path, std::atomic<bool> &stop_requested)
{
    uint64 charsetSize = static_cast<uint64>(charset.size());
    if (charsetSize == 0)
        return;
    for (uint64 idx = start_idx; idx < end_idx && !foundFlag.load(std::memory_order_acquire) && !stop_requested.load(std::memory_order_acquire); ++idx)
    {
        std::string pwd(length, charset[0]);
        uint64 current = idx;
        for (int i = 0; i < length; ++i)
        {
            pwd[length - 1 - i] = charset[current % charsetSize];
            current /= charsetSize;
            if (current == 0 && i < length - 1)
                break;
        }
        if (idx % 1000 == 0) { // Check every 1000 iterations
            if (!stop_flag_path.empty() && stop_flag_exists(stop_flag_path)) { // Check path validity first
                // *** No serialization call here anymore ***
                update_output("INFO: Stop flag detected by sequential worker " + std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id())) + ".");
                stop_requested.store(true, std::memory_order_release); // Just set the flag
                break; // Exit the loop
            }
        }
        bool skip = (filter && filter->contains(pwd));
        if (!skip)
        {
            if (tryPassword(pwd, archivePath))
            {
                bool expected = false;
                if (foundFlag.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
                {
                    std::lock_guard<std::mutex> lk(foundMutex);
                    foundPassword_out = pwd;
                }
                return;
            }
            else if (filter && filterMutex)
            {
                std::lock_guard<std::mutex> filterLk(*filterMutex);
                filter->insert(pwd);
            }
        }
    }
}

// --- Worker for Asc/Desc pattern mode (using local indices per length) ---
static void pattern_index_worker(
    uint64_t start_idx, uint64_t end_idx, const std::vector<std::string> &segments, const std::string &charset, int total_length, const std::string &archivePath,
    std::atomic<bool> &foundFlag, std::string &foundPassword_out, std::mutex &foundMutex,
    BloomFilter *filter, std::mutex *filterMutex, const std::string &stop_flag_path, std::atomic<bool> &stop_requested)
{
    for (uint64 idx = start_idx; idx < end_idx && !foundFlag.load(std::memory_order_acquire) && !stop_requested.load(std::memory_order_acquire); ++idx)
    {
        if (idx % 1000 == 0)
        {
            if (stop_flag_exists(stop_flag_path))
            {
                if (filter && filterMutex)
                {
                    std::lock_guard<std::mutex> lock(*filterMutex);
                    filter->serialize(skipListFilePath);
                    update_output("INFO: Stop flag detected by pattern worker...");
                }
                stop_requested.store(true, std::memory_order_release);
                break;
            }
        }
        std::string pwd;
        if (getPatternPasswordByIndex(idx, segments, charset, total_length, pwd))
        {
            bool skip = (filter && filter->contains(pwd));
            if (!skip)
            {
                if (tryPassword(pwd, archivePath))
                {
                    bool expected = false;
                    if (foundFlag.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
                    {
                        std::lock_guard<std::mutex> lk(foundMutex);
                        foundPassword_out = pwd;
                    }
                    return;
                }
                else if (filter && filterMutex)
                {
                    std::lock_guard<std::mutex> filterLk(*filterMutex);
                    filter->insert(pwd);
                }
            }
        }
        else
        {
            update_output("WARN: getPatternPasswordByIndex failed for index " + std::to_string(idx) + ", length " + std::to_string(total_length));
        }
    }
}

// --- Worker for standard random mode (shuffled global indices) ---
static void shuffled_index_worker(
    uint64 start_vector_idx, uint64 end_vector_idx, const std::vector<uint64> &shuffled_indices, uint64 global_index_offset, const std::string &charset, int max_length, const std::string &archivePath,
    std::atomic<bool> &foundFlag, std::string &foundPassword_out, std::mutex &foundMutex,
    BloomFilter *filter, std::mutex *filterMutex, const std::string &stop_flag_path, std::atomic<bool> &stop_requested)
{
    for (uint64 vec_idx = start_vector_idx; vec_idx < end_vector_idx && !foundFlag.load(std::memory_order_acquire) && !stop_requested.load(std::memory_order_acquire); ++vec_idx)
    {
        uint64 relative_index = shuffled_indices[vec_idx];
        uint64 global_password_index = relative_index + global_index_offset;
        if (vec_idx % 1000 == 0) { // Check every 1000 iterations
            if (!stop_flag_path.empty() && stop_flag_exists(stop_flag_path)) { // Check path validity first
               // *** No serialization call here anymore ***
               update_output("INFO: Stop flag detected by shuffled_index_worker " + std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id())) + ".");
               stop_requested.store(true, std::memory_order_release); // Just set the flag
               break; // Exit the loop
           }
       }
        std::string pwd;
        if (getPasswordByIndex(global_password_index, charset, max_length, pwd))
        {
            bool skip = (filter && filter->contains(pwd));
            if (!skip)
            {
                if (tryPassword(pwd, archivePath))
                {
                    bool expected = false;
                    if (foundFlag.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
                    {
                        std::lock_guard<std::mutex> lk(foundMutex);
                        foundPassword_out = pwd;
                    }
                    return;
                }
                else if (filter && filterMutex)
                {
                    std::lock_guard<std::mutex> filterLk(*filterMutex);
                    filter->insert(pwd);
                }
            }
        }
        else
        {
            update_output("WARN: getPasswordByIndex failed for global index " + std::to_string(global_password_index));
        }
    }
}

// --- Worker for random pattern mode (shuffled global pattern indices) ---
// (Needs stop_flag_exists, getPatternPasswordByGlobalIndex, tryPassword defined above)
static void shuffled_pattern_worker(
    uint64_t start_vector_idx, uint64_t end_vector_idx, const std::vector<uint64_t> &shuffled_indices, const std::vector<std::string> &segments, const std::string &charset,
    int min_len, int max_len, const std::map<int, uint64_t> &per_length_counts, const std::string &archivePath,
    std::atomic<bool> &foundFlag, std::string &foundPassword_out, std::mutex &foundMutex,
    BloomFilter *filter, std::mutex *filterMutex, const std::string &stop_flag_path, std::atomic<bool> &stop_requested)
{
    for (uint64 vec_idx = start_vector_idx; vec_idx < end_vector_idx && !foundFlag.load(std::memory_order_acquire) && !stop_requested.load(std::memory_order_acquire); ++vec_idx)
    {
        if (vec_idx % 1000 == 0)
        {
            // *** Fixed call: Uses the correctly defined function now ***
            if (stop_flag_exists(stop_flag_path))
            {
                if (filter && filterMutex)
                {
                    std::lock_guard<std::mutex> lock(*filterMutex);
                    filter->serialize(skipListFilePath);
                    update_output("INFO: Stop flag detected by shuffled pattern worker...");
                }
                stop_requested.store(true, std::memory_order_release);
                break;
            }
        }
        uint64 global_pattern_index = shuffled_indices[vec_idx];
        std::string pwd;
        if (getPatternPasswordByGlobalIndex(global_pattern_index, segments, charset, min_len, max_len, per_length_counts, pwd))
        {
            bool skip = (filter && filter->contains(pwd));
            if (!skip)
            {
                // *** Fixed call: Uses the correctly defined function now ***
                if (tryPassword(pwd, archivePath))
                {
                    bool expected = false;
                    if (foundFlag.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
                    {
                        std::lock_guard<std::mutex> lk(foundMutex);
                        foundPassword_out = pwd;
                    }
                    return;
                }
                else if (filter && filterMutex)
                {
                    std::lock_guard<std::mutex> filterLk(*filterMutex);
                    filter->insert(pwd);
                }
            }
        }
        else
        {
            update_output("WARN: getPatternPasswordByGlobalIndex failed for global pattern index " + std::to_string(global_pattern_index));
        }
    }
}

// ================================================================
// ===     RECURSIVE GENERATORS (Optional Fallback - Not Used)  ===
// ================================================================
// Forward declare for mutual recursion
void generate_pattern_passwords(const std::vector<std::string> &segments, const std::string &charset, int length, std::string current_pwd, size_t segment_idx, int pos, std::atomic<bool> &foundFlag, std::string &foundPassword_out, std::mutex &foundMutex, BloomFilter *filter, std::mutex *filterMutex, const std::string &archivePath, const std::string &stop_flag_path, std::atomic<bool> &stop_requested);

void generate_suffix_combinations(const std::string &charset, std::string &suffix, size_t idx, const std::string &current_pwd, size_t segment_idx, int pos, int length, const std::vector<std::string> &segments, std::atomic<bool> &foundFlag, std::string &foundPassword_out, std::mutex &foundMutex, BloomFilter *filter, std::mutex *filterMutex, const std::string &archivePath, const std::string &stop_flag_path, std::atomic<bool> &stop_requested)
{
    if (idx == suffix.length())
    {
        std::string new_pwd = current_pwd + suffix;
        generate_pattern_passwords(segments, charset, length, new_pwd, segment_idx + 1, pos, foundFlag, foundPassword_out, foundMutex, filter, filterMutex, archivePath, stop_flag_path, stop_requested);
        return;
    }
    for (char c : charset)
    {
        if (foundFlag.load(std::memory_order_acquire) || stop_requested.load(std::memory_order_acquire))
            break;
        suffix[idx] = c;
        generate_suffix_combinations(charset, suffix, idx + 1, current_pwd, segment_idx, pos, length, segments, foundFlag, foundPassword_out, foundMutex, filter, filterMutex, archivePath, stop_flag_path, stop_requested);
    }
}

void generate_pattern_passwords(const std::vector<std::string> &segments, const std::string &charset, int length, std::string current_pwd, size_t segment_idx, int pos, std::atomic<bool> &foundFlag, std::string &foundPassword_out, std::mutex &foundMutex, BloomFilter *filter, std::mutex *filterMutex, const std::string &archivePath, const std::string &stop_flag_path, std::atomic<bool> &stop_requested)
{
    if (segment_idx == segments.size())
    {
        if (pos == length && !foundFlag.load(std::memory_order_acquire) && !stop_requested.load(std::memory_order_acquire))
        {
            if (stop_flag_exists(stop_flag_path))
            {
                if (filter && filterMutex)
                {
                    std::lock_guard<std::mutex> lock(*filterMutex);
                    filter->serialize(skipListFilePath);
                    update_output("INFO: Stop flag detected (recursive gen)...");
                }
                stop_requested.store(true, std::memory_order_release);
                return;
            }
            bool skip = (filter && filter->contains(current_pwd));
            if (!skip)
            {
                if (tryPassword(current_pwd, archivePath))
                {
                    std::lock_guard<std::mutex> lock(foundMutex);
                    if (!foundFlag.load(std::memory_order_acquire))
                    {
                        foundPassword_out = current_pwd;
                        foundFlag.store(true, std::memory_order_release);
                    }
                }
                else if (filter && filterMutex)
                {
                    std::lock_guard<std::mutex> filterLock(*filterMutex);
                    filter->insert(current_pwd);
                }
            }
        }
        return;
    }
    if (foundFlag.load(std::memory_order_acquire) || stop_requested.load(std::memory_order_acquire))
        return;
    const std::string &segment = segments[segment_idx];
    if (segment == "*")
    {
        int remaining_fixed = 0;
        for (size_t i = segment_idx + 1; i < segments.size(); ++i)
        {
            if (segments[i] == "?")
                remaining_fixed++;
            else if (segments[i] != "*")
                remaining_fixed += segments[i].length();
        }
        int max_star_len = length - pos - remaining_fixed;
        if (max_star_len < 0)
            return;
        for (int star_len = 0; star_len <= max_star_len && !foundFlag.load(std::memory_order_acquire) && !stop_requested.load(std::memory_order_acquire); ++star_len)
        {
            std::string suffix(star_len, ' ');
            generate_suffix_combinations(charset, suffix, 0, current_pwd, segment_idx, pos + star_len, length, segments, foundFlag, foundPassword_out, foundMutex, filter, filterMutex, archivePath, stop_flag_path, stop_requested);
        }
    }
    else if (segment == "?")
    {
        if (pos + 1 <= length)
        {
            for (char c : charset)
            {
                if (foundFlag.load(std::memory_order_acquire) || stop_requested.load(std::memory_order_acquire))
                    break;
                std::string new_pwd = current_pwd + c;
                generate_pattern_passwords(segments, charset, length, new_pwd, segment_idx + 1, pos + 1, foundFlag, foundPassword_out, foundMutex, filter, filterMutex, archivePath, stop_flag_path, stop_requested);
            }
        }
    }
    else
    {
        if (static_cast<size_t>(pos) + segment.length() <= static_cast<size_t>(length))
        {
            std::string new_pwd = current_pwd + segment;
            generate_pattern_passwords(segments, charset, length, new_pwd, segment_idx + 1, pos + segment.length(), foundFlag, foundPassword_out, foundMutex, filter, filterMutex, archivePath, stop_flag_path, stop_requested);
        }
    }
}

// ================================================================
// ===                MAIN BRUTE-FORCE DISPATCHER               ===
// ================================================================
// ================================================================
// ===                MAIN BRUTE-FORCE DISPATCHER               ===
// ================================================================
std::string brute_force_worker_combined(
    const std::string &charset, int min_length, int max_length, const std::string &archivePath,
    CrackingMode mode, BloomFilter *filter, std::mutex *filterMutex, int checkpointInterval, const std::string &pattern)
{
    update_output("INFO: Starting brute-force worker...");
    auto startTime = std::chrono::high_resolution_clock::now();
    auto lastCheckpointTime = startTime;
    uint64 charsetSize = static_cast<uint64>(charset.size());
    if (charsetSize == 0 || min_length <= 0 || max_length < min_length)
    {
        update_output("ERROR: Invalid parameters passed to brute_force_worker_combined.");
        return "";
    }

    unsigned int numThreads = std::thread::hardware_concurrency();
    if (numThreads == 0)
        numThreads = 4;
    numThreads = std::max(1u, numThreads);
    update_output("INFO: Using " + std::to_string(numThreads) + " worker threads.");

    std::atomic<bool> foundFlag(false);
    std::string foundPassword_internal;
    std::mutex foundMutex;
    std::atomic<bool> stop_requested(false); // Atomic stop flag shared across threads and main logic
    std::string stop_flag_path = "";         // Initialize empty
    if (filter && !skipListFilePath.empty()) { // Only define stop path if filter is active
         stop_flag_path = skipListFilePath + ".stop";
    }


    // Helper lambda for combination calculation (avoids code duplication)
    auto calculate_combinations = [&](int length) -> uint64
    {
        if (length <= 0) return 0;
        uint64 combinations = 1;
        for (int i = 0; i < length; ++i)
        {
            if (combinations > (std::numeric_limits<uint64>::max)() / charsetSize)
            {
                throw std::overflow_error("Combination calculation overflow for length " + std::to_string(length));
            }
            combinations *= charsetSize;
        }
        return combinations;
    };

    // Helper lambda for checkpointing
    auto checkpoint_filter_func = [&]()
    {
        // Checkpoint only if filter is enabled, interval > 0, and stop hasn't been requested
        if (filter && filterMutex && !skipListFilePath.empty() && checkpointInterval > 0 && !stop_requested.load(std::memory_order_acquire))
        {
            auto now = std::chrono::high_resolution_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - lastCheckpointTime).count() >= checkpointInterval)
            {
                update_output("INFO: Checkpoint interval reached. Saving skip list state...");
                std::lock_guard<std::mutex> lock(*filterMutex);
                if (filter->serialize(skipListFilePath))
                {
                    update_output("INFO: Skip list checkpoint saved successfully to: " + skipListFilePath);
                }
                else
                {
                    update_output("ERROR: Failed to save skip list checkpoint!");
                }
                lastCheckpointTime = now; // Update last checkpoint time regardless of success
            }
        }
    };

    // Helper lambda to check stop flag AND set atomic bool
    auto check_stop_flag = [&]() -> bool {
        if (!stop_flag_path.empty() && stop_flag_exists(stop_flag_path)) {
            if (!stop_requested.load(std::memory_order_acquire)) { // Avoid redundant messages
                update_output("INFO: Stop flag file detected.");
            }
            stop_requested.store(true, std::memory_order_release);
            return true;
        }
        return stop_requested.load(std::memory_order_acquire); // Also return true if already set
    };


    try
    {
        if (!pattern.empty())
        {
            // --- PATTERN MATCHING MODE ---
            update_output("INFO: Pattern matching mode enabled.");
            auto segments = parse_pattern(pattern);
            auto info = calculate_pattern_info(segments);
            int initial_fixed_length = info.fixed_length;
            int num_stars = info.num_stars;

            // Adjust min/max length based on pattern constraints
            if (min_length < initial_fixed_length)
            {
                update_output("INFO: Adjusted min_length from " + std::to_string(min_length) + " to pattern minimum " + std::to_string(initial_fixed_length));
                min_length = initial_fixed_length;
            }
            if (num_stars == 0) { // No wildcards means fixed length
                if (max_length != initial_fixed_length) {
                    update_output("INFO: Adjusted max_length to " + std::to_string(initial_fixed_length) + " (pattern has fixed length)");
                    max_length = initial_fixed_length;
                }
                 if (min_length != initial_fixed_length) { // Should be caught above, but double-check
                    min_length = initial_fixed_length;
                }
            }
            if (max_length < min_length) // Final sanity check
            {
                update_output("INFO: Corrected max_length to " + std::to_string(min_length) + " (max < min)");
                max_length = min_length;
            }

            if (mode == CrackingMode::RANDOM_LCG)
            {
                if (num_stars > 1)
                {
                    update_output("WARN: Random mode is currently unsupported for multi-star patterns. Falling back to ASCENDING order.");
                    mode = CrackingMode::ASCENDING; // Fallback for multi-star random
                }
                else
                {
                    // --- RANDOM PATTERN MODE ---
                    update_output("INFO: Calculating total combinations for random pattern mode...");
                    uint64 total_pattern_combinations = 0;
                    std::map<int, uint64_t> per_length_counts;
                    bool calculation_ok = true;

                    for (int L = min_length; L <= max_length; ++L)
                    {
                        // *** ADD STOP CHECK *** before potentially long calculation
                        if (check_stop_flag()) { calculation_ok = false; break; }

                        std::optional<uint64_t> countOpt = calculate_pattern_combinations(segments, charsetSize, L);
                        if (!countOpt)
                        {
                            update_output("ERROR: Pattern combination calculation failed (overflow?) for length " + std::to_string(L));
                            calculation_ok = false;
                            break;
                        }
                        uint64_t count_this_length = countOpt.value();
                        if (count_this_length > 0)
                        {
                            per_length_counts[L] = count_this_length;
                            if (total_pattern_combinations > std::numeric_limits<uint64>::max() - count_this_length)
                            {
                                update_output("ERROR: Total pattern combination calculation overflowed.");
                                calculation_ok = false;
                                break;
                            }
                            total_pattern_combinations += count_this_length;
                        }
                    }

                    if (check_stop_flag()) { /* Handled by break */ }
                    else if (!calculation_ok) {
                        update_output("INFO: Calculation issue or stop detected. Falling back to ASCENDING length order if needed.");
                        mode = CrackingMode::ASCENDING; // Fallback if calculation failed
                    }
                    else if (total_pattern_combinations == 0) {
                        update_output("INFO: Pattern generates 0 combinations in the specified length range.");
                        // No work to do, will exit naturally
                    }
                    else {
                        update_output("INFO: Total pattern combinations in range: " + std::to_string(total_pattern_combinations));
                        const uint64 MAX_REASONABLE_INDICES_RAM = (4ULL * 1024 * 1024 * 1024) / sizeof(uint64); // Approx 4GB RAM limit for index vector
                        if (total_pattern_combinations > MAX_REASONABLE_INDICES_RAM) {
                            update_output("ERROR: Pattern space too large for random mode RAM usage ("
                                          + std::to_string(total_pattern_combinations * sizeof(uint64) / (1024*1024)) + " MB needed). Falling back to ASCENDING order.");
                            mode = CrackingMode::ASCENDING; // Fallback if too large for RAM
                        }
                        else {
                            // --- Generate and Shuffle Indices for Random Pattern ---
                            update_output("INFO: Generating and shuffling " + std::to_string(total_pattern_combinations) + " pattern indices...");
                            std::vector<uint64> indices(total_pattern_combinations);
                            std::iota(indices.begin(), indices.end(), 0ULL);

                            // *** ADD STOP CHECK *** before potentially long shuffle
                            if (check_stop_flag()) { /* Will skip shuffling and threads */ }
                            else {
                                uint64 seed_value;
                                std::random_device rd;
                                if (rd.entropy() > 0) { seed_value = static_cast<uint64>(rd()) << 32 | rd(); }
                                else { seed_value = static_cast<uint64>(std::chrono::high_resolution_clock::now().time_since_epoch().count()); }
                                std::mt19937_64 rng(seed_value);
                                std::shuffle(indices.begin(), indices.end(), rng);
                                update_output("INFO: Pattern indices shuffled.");

                                // *** ADD STOP CHECK *** after shuffling, before threads
                                if (check_stop_flag()) { /* Will skip threads */ }
                                else {
                                    uint64 itemsPerThread = (total_pattern_combinations + numThreads - 1) / numThreads;
                                    if (itemsPerThread == 0) itemsPerThread = 1;

                                    std::vector<std::thread> threads;
                                    threads.reserve(numThreads);
                                    for (unsigned int t = 0; t < numThreads; ++t) {
                                        if (check_stop_flag()) break; // Check before spawning each thread
                                        uint64 startVecIdx = t * itemsPerThread;
                                        uint64 endVecIdx = std::min(startVecIdx + itemsPerThread, total_pattern_combinations);
                                        if (startVecIdx >= endVecIdx) break;

                                        threads.emplace_back(shuffled_pattern_worker, startVecIdx, endVecIdx,
                                                             std::cref(indices), std::cref(segments), std::cref(charset),
                                                             min_length, max_length, std::cref(per_length_counts), std::cref(archivePath),
                                                             std::ref(foundFlag), std::ref(foundPassword_internal), std::ref(foundMutex),
                                                             filter, filterMutex, std::cref(stop_flag_path), std::ref(stop_requested));
                                    }

                                    update_output("INFO: Waiting for shuffled pattern worker threads...");
                                    for (auto &th : threads) { if (th.joinable()) th.join(); }
                                    update_output("INFO: Shuffled pattern worker threads joined.");
                                    checkpoint_filter_func(); // Checkpoint after joining
                                }
                            }
                        }
                    }
                }
            } // End of RANDOM_LCG pattern mode specific logic

            // --- ASCENDING/DESCENDING PATTERN MODE (or fallback) ---
            if (mode == CrackingMode::ASCENDING || mode == CrackingMode::DESCENDING) {
                int start_len = (mode == CrackingMode::ASCENDING) ? min_length : max_length;
                int end_len   = (mode == CrackingMode::ASCENDING) ? max_length : min_length;
                int step      = (mode == CrackingMode::ASCENDING) ? 1 : -1;

                int current_len = start_len;
                // Main loop iterating through lengths for pattern mode
                while ((step == 1 ? current_len <= end_len : current_len >= end_len)
                       && !foundFlag.load(std::memory_order_acquire)
                       && !check_stop_flag()) // *** ADD STOP CHECK *** here
                {
                    int L = current_len;
                    std::optional<uint64_t> combinationsOpt = calculate_pattern_combinations(segments, charsetSize, L);
                    std::string combo_str = "N/A";
                    uint64_t totalCombinationsThisLength = 0;

                    if (!combinationsOpt) {
                        update_output("WARN: Cannot calculate combinations (overflow?) for pattern length " + std::to_string(L) + ". Skipping.");
                        current_len += step;
                        continue;
                    }

                    totalCombinationsThisLength = combinationsOpt.value();
                    if (totalCombinationsThisLength == 0) {
                        // update_output("DEBUG: Pattern length " + std::to_string(L) + " yields 0 combinations."); // Optional debug
                        current_len += step;
                        continue;
                    }
                    combo_str = std::to_string(totalCombinationsThisLength);

                    update_output("INFO: Testing pattern matching passwords of length " + std::to_string(L) +
                                  " (Combinations: " + combo_str + ")...");

                    uint64 itemsPerThread = (totalCombinationsThisLength + numThreads - 1) / numThreads;
                    if (itemsPerThread == 0) itemsPerThread = 1;

                    std::vector<std::thread> threads;
                    threads.reserve(numThreads);
                    for (unsigned int t = 0; t < numThreads; ++t) {
                         if (check_stop_flag()) break; // Check before spawning each thread
                        uint64 startIdx = t * itemsPerThread;
                        uint64 endIdx = std::min(startIdx + itemsPerThread, totalCombinationsThisLength);
                        if (startIdx >= endIdx) break;

                        threads.emplace_back(pattern_index_worker, startIdx, endIdx,
                                             std::cref(segments), std::cref(charset), L, std::cref(archivePath),
                                             std::ref(foundFlag), std::ref(foundPassword_internal), std::ref(foundMutex),
                                             filter, filterMutex, std::cref(stop_flag_path), std::ref(stop_requested));
                    }

                    update_output("INFO: Waiting for pattern worker threads for length " + std::to_string(L) + "...");
                    for (auto &th : threads) { if (th.joinable()) th.join(); }
                    update_output("INFO: Pattern worker threads joined for length " + std::to_string(L) + ".");
                    checkpoint_filter_func(); // Checkpoint after joining threads for this length

                    // No need to check foundFlag or stop_requested again here, the outer loop does it.
                    current_len += step; // Move to next length
                }
            } // End Asc/Desc Pattern Mode
        } // End Pattern Matching Mode (!pattern.empty())
        else
        {
            // --- STANDARD BRUTE-FORCE MODE (No Pattern) ---
            if (mode == CrackingMode::ASCENDING || mode == CrackingMode::DESCENDING) {
                int start_len = (mode == CrackingMode::ASCENDING) ? min_length : max_length;
                int end_len   = (mode == CrackingMode::ASCENDING) ? max_length : min_length;
                int step      = (mode == CrackingMode::ASCENDING) ? 1 : -1;

                // Main loop iterating through lengths for standard mode
                for (int length = start_len;
                     (step == 1 ? length <= end_len : length >= end_len)
                     && !foundFlag.load(std::memory_order_acquire)
                     && !check_stop_flag(); // *** ADD STOP CHECK *** here
                     length += step)
                {
                    uint64 totalCombinationsThisLength = 0;
                    try {
                        totalCombinationsThisLength = calculate_combinations(length);
                    } catch (const std::overflow_error &e) {
                        update_output("WARN: Combination calculation overflow for length " + std::to_string(length) + ". Skipping.");
                        continue; // Skip this length if calculation fails
                    }

                    if (totalCombinationsThisLength == 0) continue;

                    update_output("INFO: Testing passwords of length " + std::to_string(length) +
                                  " (Combinations: " + std::to_string(totalCombinationsThisLength) + ")...");

                    uint64 itemsPerThread = (totalCombinationsThisLength + numThreads - 1) / numThreads;
                    if (itemsPerThread == 0) itemsPerThread = 1;

                    std::vector<std::thread> threads;
                    threads.reserve(numThreads);
                    for (unsigned int t = 0; t < numThreads; ++t) {
                        if (check_stop_flag()) break; // Check before spawning each thread
                        uint64 startIdx = t * itemsPerThread;
                        uint64 endIdx = std::min(startIdx + itemsPerThread, totalCombinationsThisLength);
                        if (startIdx >= endIdx) break;

                        threads.emplace_back(sequential_password_worker, length, startIdx, endIdx,
                                             std::cref(charset), std::cref(archivePath),
                                             std::ref(foundFlag), std::ref(foundPassword_internal), std::ref(foundMutex),
                                             filter, filterMutex, std::cref(stop_flag_path), std::ref(stop_requested));
                    }

                    update_output("INFO: Waiting for worker threads for length " + std::to_string(length) + "...");
                    for (auto &th : threads) { if (th.joinable()) th.join(); }
                    update_output("INFO: Worker threads joined for length " + std::to_string(length) + ".");
                    checkpoint_filter_func(); // Checkpoint after joining threads for this length

                    // No need to check foundFlag or stop_requested again here, the outer loop does it.
                }
            } // End Asc/Desc Standard Mode
            else { // Standard RANDOM_LCG Mode
                update_output("INFO: Calculating total combinations for random mode...");
                uint64 total_passwords_prefix = 0;
                uint64 total_passwords_target = 0;
                bool calculation_ok = true;

                for (int len = 1; len < min_length; ++len) {
                    // *** ADD STOP CHECK ***
                    if (check_stop_flag()) { calculation_ok = false; break; }
                    try {
                        uint64 comb = calculate_combinations(len);
                        if (total_passwords_prefix > (std::numeric_limits<uint64>::max)() - comb) {
                            throw std::overflow_error("Overflow calculating total prefix password count.");
                        }
                        total_passwords_prefix += comb;
                    } catch (const std::exception& e) {
                         update_output("ERROR: " + std::string(e.what()));
                         calculation_ok = false; break;
                    }
                }

                if (calculation_ok) {
                    for (int len = min_length; len <= max_length; ++len) {
                         // *** ADD STOP CHECK ***
                        if (check_stop_flag()) { calculation_ok = false; break; }
                        try {
                            uint64 comb = calculate_combinations(len);
                             if (total_passwords_target > (std::numeric_limits<uint64>::max)() - comb) {
                                throw std::overflow_error("Overflow calculating total target password count.");
                            }
                            total_passwords_target += comb;
                        } catch (const std::exception& e) {
                            update_output("ERROR: " + std::string(e.what()));
                            calculation_ok = false; break;
                        }
                    }
                }

                if (check_stop_flag()) { /* Handled by break */ }
                else if (!calculation_ok) {
                    update_output("INFO: Calculation issue or stop detected during random mode setup.");
                    // Will exit naturally as target_count might be 0 or RAM check will fail
                }
                else if (total_passwords_target == 0) {
                    update_output("WARN: Calculated total passwords in target range is zero.");
                } else {
                    update_output("INFO: Total passwords to test (lengths " + std::to_string(min_length) + " to " + std::to_string(max_length) + "): " + std::to_string(total_passwords_target));

                    const uint64 MAX_REASONABLE_INDICES_RAM = (4ULL * 1024 * 1024 * 1024) / sizeof(uint64);
                    if (total_passwords_target > MAX_REASONABLE_INDICES_RAM) {
                        update_output("ERROR: Target password space too large for shuffled index mode RAM usage.");
                        // Cannot proceed with random mode
                    } else {
                        update_output("INFO: Generating and shuffling target indices...");
                        std::vector<uint64> indices(total_passwords_target);
                        std::iota(indices.begin(), indices.end(), 0ULL);

                        // *** ADD STOP CHECK *** before potentially long shuffle
                        if (check_stop_flag()) { /* Skip shuffling and threads */ }
                        else {
                            uint64 seed_value;
                            std::random_device rd;
                            if (rd.entropy() > 0) { seed_value = static_cast<uint64>(rd()) << 32 | rd(); }
                            else { seed_value = static_cast<uint64>(std::chrono::high_resolution_clock::now().time_since_epoch().count()); }
                            std::mt19937_64 rng(seed_value);
                            std::shuffle(indices.begin(), indices.end(), rng);
                            update_output("INFO: Index vector generated and shuffled.");

                             // *** ADD STOP CHECK *** after shuffling, before threads
                            if (check_stop_flag()) { /* Skip threads */ }
                            else {
                                uint64 itemsPerThread = (total_passwords_target + numThreads - 1) / numThreads;
                                if (itemsPerThread == 0) itemsPerThread = 1;

                                std::vector<std::thread> threads;
                                threads.reserve(numThreads);
                                for (unsigned int t = 0; t < numThreads; ++t) {
                                    if (check_stop_flag()) break; // Check before spawning each thread
                                    uint64 startVecIdx = t * itemsPerThread;
                                    uint64 endVecIdx = std::min(startVecIdx + itemsPerThread, total_passwords_target);
                                    if (startVecIdx >= endVecIdx) break;

                                    threads.emplace_back(shuffled_index_worker, startVecIdx, endVecIdx,
                                                         std::cref(indices), total_passwords_prefix,
                                                         std::cref(charset), max_length, std::cref(archivePath),
                                                         std::ref(foundFlag), std::ref(foundPassword_internal), std::ref(foundMutex),
                                                         filter, filterMutex, std::cref(stop_flag_path), std::ref(stop_requested));
                                }
                                update_output("INFO: Waiting for shuffled index worker threads...");
                                for (auto &th : threads) { if (th.joinable()) th.join(); }
                                update_output("INFO: Shuffled index worker threads joined.");
                                checkpoint_filter_func(); // Checkpoint after joining
                            }
                        }
                    }
                }
            } // End Random Standard Mode
        } // End Standard Brute-Force Mode (else pattern.empty())
    } // End try block
    catch (const std::exception &e)
    {
        update_output("FATAL ERROR: " + std::string(e.what()));
        // Attempt final save even on exception if filter is valid
        if (filter && filterMutex && !skipListFilePath.empty() && filter->isValid()) {
             update_output("INFO: Attempting final save of skip list state after error...");
             std::lock_guard<std::mutex> lock(*filterMutex);
             if (!filter->serialize(skipListFilePath)) {
                 update_output("ERROR: Failed to save final skip list state after error!");
             }
        }
        return ""; // Return empty on error
    }

    // --- Finalization ---
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    update_output("INFO: Brute-force worker processing finished in " + std::to_string(duration.count() / 1000.0) + " seconds.");

    // Determine if the process was stopped by user request (check atomic flag again)
    bool stopped = stop_requested.load(std::memory_order_acquire);

    // Perform final save ONLY if filter is enabled, VALID, and (found or stopped)
    bool performFinalSave = filter                                                     // Filter pointer exists
                            && filterMutex                                             // Mutex pointer exists
                            && !skipListFilePath.empty()                               // File path is set
                            && filter->isValid()                                       // <<< CRITICAL CHECK >>> Filter internal state is valid
                            && (foundFlag.load(std::memory_order_acquire) || stopped); // Reason to save

    if (performFinalSave)
    {
        update_output("INFO: Performing final save of skip list state...");
        std::lock_guard<std::mutex> lock(*filterMutex);
        if (filter->serialize(skipListFilePath))
        { // Call serialize only if all conditions met
            update_output("INFO: Skip list final state saved successfully to: " + skipListFilePath);
        }
        else
        {
            update_output("ERROR: Failed to save final skip list state!");
        }
    }
    else
    {
        // Log why final save didn't happen (optional but helpful)
        if (filter && !skipListFilePath.empty())
        { // Only log if filter was intended
            if (!filter->isValid())
            {
                update_output("INFO: Final skip list save skipped because filter became invalid during run.");
            }
            else if (!foundFlag.load(std::memory_order_acquire) && !stopped)
            {
                update_output("INFO: Final skip list save skipped (process finished normally without finding password or being stopped).");
            }
            else if (!foundFlag.load(std::memory_order_acquire) && stopped)
            {
                update_output("INFO: Final skip list save skipped (process stopped but filter might be invalid or save condition not met).");
            }
        }
        else if (!skipListFilePath.empty())
        {
            update_output("INFO: Final skip list save skipped (filter pointer was null or path empty).");
        }
    }

    // --- Return Result ---
    if (foundFlag.load(std::memory_order_acquire))
    {
        std::lock_guard<std::mutex> lk(foundMutex); // Ensure password string is read safely
        return foundPassword_internal;
    }
    else if (stopped)
    {
        // Don't report "Password not found" if user stopped it.
        update_output("INFO: Process stopped by user request.");
        return ""; // Return empty string indicating stop, not failure
    }
    else
    {
        // Only report "not found" if it finished normally without finding it.
        update_output("INFO: Exhausted search space without finding password.");
        return ""; // Return empty string indicating not found
    }
}