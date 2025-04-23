#include "brute_force.h" // Uses CrackingMode now
#include "bloom_filter.h"// Include Bloom Filter header
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdio>
#include <algorithm>
#include <cctype>
#include <mutex>     // Include mutex for Bloom Filter access
#include <limits>    // For numeric_limits

// Platform-specific includes
#ifdef _WIN32
    // --- FIX: Define NOMINMAX before including Windows.h ---
    #ifndef NOMINMAX
    #define NOMINMAX
    #endif
    // --- End FIX ---
    #include <windows.h>
    #include <shlwapi.h> // For PathFileExists etc.
    // #pragma comment(lib, "Shlwapi.lib") // Link against Shlwapi.lib
#else
    #include <unistd.h> // For readlink, access
    #include <limits.h> // For PATH_MAX (less reliable)
    #include <sys/stat.h> // For stat() to check file existence/type
    #include <cstdlib>   // For popen, pclose
#endif

// Global path for 7z executable
std::string sevenZipPath;

// Globals for Skip List
std::string skipListFilePath;
int checkpointIntervalSeconds = 0;
BloomFilter skipFilter;
std::mutex skipFilterMutex;


// Output function (prints to stdout for Python)
void update_output(const std::string& message) {
    // Ensure flush for immediate Python reading, especially if output is redirected
    std::cout << message << std::endl;
}

// Function to find the directory containing the current executable (no changes needed)
std::string getExecutablePathDir() {
    std::string path_str;
    char* path_buf = nullptr;

#ifdef _WIN32
    DWORD buf_size = MAX_PATH;
    DWORD len = 0;
    do {
        delete[] path_buf;
        path_buf = new (std::nothrow) char[buf_size];
        if (!path_buf) return ""; // Allocation failed
        // Use GetModuleFileNameA for char buffer
        len = GetModuleFileNameA(nullptr, path_buf, buf_size);
        if (len == 0) { // Error getting path
             delete[] path_buf; return "";
        }
        // Check if buffer was large enough (len < buf_size)
        // If len == buf_size, the path might be truncated, need larger buffer.
        if (len < buf_size) break;
        buf_size *= 2; // Double buffer size and retry
    } while (true);
    path_str = path_buf;
    delete[] path_buf;

#else // Linux/macOS
    size_t buf_size = 1024; // Initial reasonable size
    ssize_t len = -1;
    do {
        delete[] path_buf;
        path_buf = new (std::nothrow) char[buf_size];
        if (!path_buf) return "";
        // Try /proc/self/exe first (Linux standard)
        len = readlink("/proc/self/exe", path_buf, buf_size - 1); // Leave space for null terminator
        #ifdef __APPLE__ // macOS specific fallback using _NSGetExecutablePath
        if (len < 0) {
             #include <mach-o/dyld.h> // For _NSGetExecutablePath
             uint32_t mac_buf_size = (uint32_t)buf_size;
             if (_NSGetExecutablePath(path_buf, &mac_buf_size) == 0) {
                 len = mac_buf_size; // Path stored, update length
             } else {
                 // Buffer was too small, need to reallocate with mac_buf_size + 1
                 delete[] path_buf;
                 buf_size = mac_buf_size + 1; // Use the size suggested by the function
                 path_buf = new (std::nothrow) char[buf_size];
                 if (!path_buf) return "";
                 if (_NSGetExecutablePath(path_buf, &mac_buf_size) == 0) {
                     len = mac_buf_size;
                 } else {
                     // Still failed? Unlikely.
                     len = -1;
                 }
             }
        }
        #endif // __APPLE__

        if (len < 0) { delete[] path_buf; return ""; } // Error reading link or path
        if (static_cast<size_t>(len) < buf_size - 1) break; // Success, fit in buffer

        // Buffer too small, double size and retry
        buf_size *= 2;
        // Add a safeguard against excessively large paths/infinite loops
        if (buf_size > 32768) { delete[] path_buf; return ""; }
    } while(true);
    path_buf[len] = '\0'; // Null-terminate the string
    path_str = path_buf;
    delete[] path_buf;
#endif

    // Get directory part (works for both / and \)
    if (!path_str.empty()) {
        size_t last_slash_idx = path_str.find_last_of("/\\");
        if (std::string::npos != last_slash_idx) {
            return path_str.substr(0, last_slash_idx);
        }
    }
    return ""; // Error or unexpected path format (e.g., root directory?)
}

// Helper to check if a file exists (no changes needed for NOMINMAX here)
bool check_executable(const std::string& path) {
#ifdef _WIN32
    DWORD fileAttr = GetFileAttributesA(path.c_str());
    // Check if it exists and is not a directory
    return (fileAttr != INVALID_FILE_ATTRIBUTES && !(fileAttr & FILE_ATTRIBUTE_DIRECTORY));
#else
    struct stat statbuf;
    // Check existence and if it's a regular file
    // Consider checking execute permission too: (statbuf.st_mode & S_IXUSR)
    // But let's rely on the OS to fail execvp if it's not executable.
    return (stat(path.c_str(), &statbuf) == 0 && S_ISREG(statbuf.st_mode));
#endif
}


int main(int argc, char *argv[]) {
    // --- Argument Parsing ---
    if (argc < 6) {
        std::cerr << "ERROR: Insufficient arguments." << std::endl;
        std::cerr << "Usage: " << (argc > 0 ? argv[0] : "ArchivePasswordCrackerCLI")
                  << " <charset> <min_length> <max_length> <archive_path> <ascending|descending|random>"
                  << " [--skip-file <path>] [--checkpoint-interval <seconds>]" << std::endl;
        update_output("ERROR: Invalid number of required arguments provided to C++ backend. Expected at least 5.");
        return 2; // Argument error exit code
    }

    std::string pattern; // Declare pattern variable
    for (int i = 6; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "--pattern" || arg == "-p") && i + 1 < argc) {
            pattern = argv[++i];
        } else if ((arg == "--skip-file" || arg == "-s") && i + 1 < argc) {
            skipListFilePath = argv[++i];
        } else if ((arg == "--checkpoint-interval" || arg == "-c") && i + 1 < argc) {
            try {
                checkpointIntervalSeconds = std::stoi(argv[++i]);
                if (checkpointIntervalSeconds < 0) {
                    std::cerr << "WARN: Checkpoint interval cannot be negative, using 0 (disabled)." << std::endl;
                    checkpointIntervalSeconds = 0;
                }
            } catch (const std::exception& e) {
                std::cerr << "WARN: Invalid checkpoint interval value ('" << argv[i] << "'), using 0 (disabled). Error: " << e.what() << std::endl;
                checkpointIntervalSeconds = 0;
            }
        } else {
            std::cerr << "WARN: Ignoring unknown or misplaced optional argument: '" << arg << "'" << std::endl;
        }
    }
    if (!pattern.empty()) {
        update_output("INFO: Using pattern: " + pattern);
    }
    std::string charset = argv[1];
    int min_length = 0;
    int max_length = 0;
    std::string archivePath = argv[4];
    std::string mode_str = argv[5];
    CrackingMode crack_mode;

    // Parse min_length
    try {
        min_length = std::stoi(argv[2]);
        if (min_length <= 0) throw std::invalid_argument("Min length must be positive");
    } catch (const std::exception& e) {
        std::cerr << "ERROR: Invalid min_length argument ('" << argv[2] << "'): " << e.what() << std::endl;
        update_output("ERROR: Invalid min_length argument provided ('" + std::string(argv[2]) + "').");
        return 2;
    }

    // Parse max_length
    try {
        max_length = std::stoi(argv[3]);
        if (max_length <= 0) throw std::invalid_argument("Max length must be positive");
    } catch (const std::exception& e) {
        std::cerr << "ERROR: Invalid max_length argument ('" << argv[3] << "'): " << e.what() << std::endl;
        update_output("ERROR: Invalid max_length argument provided ('" + std::string(argv[3]) + "').");
        return 2;
    }

    // Validate min <= max
    if (min_length > max_length) {
         std::cerr << "ERROR: min_length (" << min_length
                   << ") cannot be greater than max_length (" << max_length << ")." << std::endl;
        update_output("ERROR: min_length cannot be greater than max_length.");
        return 2;
    }

    // Parse mode argument
    std::transform(mode_str.begin(), mode_str.end(), mode_str.begin(),
                   [](unsigned char c){ return std::tolower(c); }); // Use lambda for safety
    if (mode_str == "descending") { crack_mode = CrackingMode::DESCENDING; }
    else if (mode_str == "ascending") { crack_mode = CrackingMode::ASCENDING; }
    else if (mode_str == "random") { crack_mode = CrackingMode::RANDOM_LCG; }
    else {
        std::cerr << "ERROR: Invalid mode argument: '" << argv[5] << "'. Must be 'ascending', 'descending', or 'random'." << std::endl;
        update_output("ERROR: Invalid mode argument provided ('" + std::string(argv[5]) + "'). Use 'ascending', 'descending', or 'random'.");
        return 2;
    }

    // --- Parse Optional Arguments ---

    // --- Find 7z executable --- (MODIFIED BLOCK STARTS HERE) ---
    std::string exeDir = getExecutablePathDir();
    if (exeDir.empty()) {
        update_output("ERROR: Could not determine the directory containing this executable. Cannot find 7z.");
        return 4; // Path error exit code
    }
    update_output("INFO: C++ Executable running from: " + exeDir);

    bool sevenZipFound = false;
    #ifdef _WIN32
        std::string separator = "\\";
        std::string exe_name = "7z.exe";
    #else
        std::string separator = "/";
        std::string exe_name = "7z";
    #endif

    // --- Strategy: ---
    // 1. Check ./bin/ relative to C++ executable (e.g., helpers/bin/) - LIKE OLD VERSION
    // 2. Check ../bin/ relative to C++ executable (e.g., helpers/../bin/ -> root/bin/) - CURRENT STRUCTURE
    // 3. (Linux/macOS only) Check system PATH as a last resort

    // 1. Check ./bin/ (relative to C++ executable's location)
    std::string path_adjacent_bin = exeDir + separator + "bin" + separator + exe_name;
    update_output("INFO: Checking for 7z in adjacent bin (e.g., helpers/bin/): " + path_adjacent_bin);
    if (check_executable(path_adjacent_bin)) {
        sevenZipPath = path_adjacent_bin;
        sevenZipFound = true;
        update_output("INFO: Found 7z in adjacent bin directory.");
    }

    // 2. Check ../bin/ (relative to C++ executable's location -> project root bin)
    std::string path_parent_bin; // Declare outside if block for logging
    if (!sevenZipFound) {
        path_parent_bin = exeDir + separator + ".." + separator + "bin" + separator + exe_name;
        // For logging clarity, indicate it points to the root bin relative to helpers/
        update_output("INFO: Checking for 7z in parent's bin (e.g., root/bin/): " + path_parent_bin);
        if (check_executable(path_parent_bin)) {
            // Use the path as calculated. The OS can resolve ".." correctly.
            sevenZipPath = path_parent_bin;
            sevenZipFound = true;
            update_output("INFO: Found 7z in parent's bin directory (root bin).");
        }
    }

    // 3. Fallback to PATH only needed on Linux/macOS if relative paths fail
    #ifndef _WIN32
        if (!sevenZipFound) {
            update_output("INFO: 7z not found locally. Checking system PATH...");
            // Use 'command -v' or similar to check PATH reliably on POSIX
             FILE *pipe = popen("command -v 7z 2>/dev/null", "r"); // Check PATH for '7z', redirect stderr
             if (pipe) {
                 char buffer[256];
                 if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                     // Found in path, remove trailing newline if present
                     std::string path_from_cmd = buffer;
                     path_from_cmd.erase(path_from_cmd.find_last_not_of(" \n\r\t")+1);
                     if (!path_from_cmd.empty() && check_executable(path_from_cmd)) {
                         sevenZipPath = path_from_cmd; // Use the full path found
                         sevenZipFound = true;
                         update_output("INFO: Found 7z in system PATH: " + sevenZipPath);
                     } else {
                          update_output("WARN: 'command -v 7z' found something, but check_executable failed for: " + path_from_cmd);
                     }
                 } else {
                     update_output("INFO: '7z' not found in system PATH via 'command -v'.");
                 }
                 // Check pclose status for more robustness if needed
                 int pipe_status = pclose(pipe);
                 if (pipe_status == -1) {
                      update_output("ERROR: pclose failed after 'command -v 7z'.");
                 } else if (WEXITSTATUS(pipe_status) != 0) {
                     // command -v might have exited non-zero if not found
                     // update_output("DEBUG: 'command -v 7z' exited with status " + std::to_string(WEXITSTATUS(pipe_status)));
                 }

             } else {
                 update_output("ERROR: Failed to run 'command -v 7z' to check PATH.");
             }
        }
    #endif

    // Final check if 7z was found
    if (!sevenZipFound) {
        update_output("ERROR: " + exe_name + " could not be found.");
        update_output("       Checked adjacent path: " + path_adjacent_bin);
        update_output("       Checked parent path:   " + (path_parent_bin.empty() ? (exeDir + separator + ".." + separator + "bin" + separator + exe_name) : path_parent_bin) ); // Recalculate if needed for log
        #ifndef _WIN32
        update_output("       Also checked system PATH.");
        #endif
        update_output("       Ensure 7z.exe (and 7z.dll on Windows) are placed correctly.");
        update_output("       Expected locations: './bin/' (adjacent) or '../bin/' (parent's bin) relative to C++ executable at " + exeDir);
        return 3; // 7z not found exit code
    } else {
        update_output("INFO: Using 7z executable: " + sevenZipPath);
    }
    // --- (MODIFIED BLOCK ENDS HERE) ---


    // --- Initialize or Load Bloom Filter ---
    if (!skipListFilePath.empty()) {
        update_output("INFO: Skip list feature enabled. File: " + skipListFilePath);
        if (checkpointIntervalSeconds > 0) {
            update_output("INFO: Checkpoint interval: " + std::to_string(checkpointIntervalSeconds) + " seconds.");
        } else {
            update_output("INFO: Automatic checkpointing disabled (only final save on exit).");
        }

        // Attempt to load existing filter first
        bool loaded = false;
        try {
            loaded = skipFilter.deserialize(skipListFilePath);
        } catch (const std::exception& e) {
             update_output("ERROR: Exception during skip list deserialization: " + std::string(e.what()));
             // Treat as if not loaded
        }

        if (loaded && skipFilter.isValid()) {
            update_output("INFO: Loaded existing skip list state. Bits: " + std::to_string(skipFilter.getNumBits()) + ", Hashes: " + std::to_string(skipFilter.getNumHashes()));
        } else {
            if (loaded) { // Loaded but invalid
                 update_output("WARN: Existing skip list file was invalid or corrupted. Creating new one.");
            } else {
                 update_output("INFO: No valid existing skip list found, or file doesn't exist. Creating new one.");
            }

            // Calculate estimated items ONLY for the target range min_length..max_length
            uint64_t estimated_items_in_range = 0;
            uint64_t cs = static_cast<uint64_t>(charset.size());
            bool overflow_occurred = false;

            if (cs > 0)
            {
                for (int len = min_length; len <= max_length; ++len)
                {
                    uint64_t combinations_this_len = 1;
                    for (int i = 0; i < len; ++i)
                    {
                        if (combinations_this_len > std::numeric_limits<uint64_t>::max() / cs)
                        {
                            overflow_occurred = true;
                            update_output("ERROR: Overflow calculating combinations for length " + std::to_string(len) + ".");
                            break;
                        }
                        combinations_this_len *= cs;
                    }
                    if (overflow_occurred)
                        break;
                    if (estimated_items_in_range > std::numeric_limits<uint64_t>::max() - combinations_this_len)
                    {
                        overflow_occurred = true;
                        update_output("ERROR: Overflow calculating total estimated items in range.");
                        break;
                    }
                    estimated_items_in_range += combinations_this_len;
                }
            }
            else
            {
                update_output("WARN: Charset size is zero, cannot estimate items for Bloom filter.");
                overflow_occurred = true;
            }

            if (overflow_occurred)
            {
                update_output("ERROR: Cannot accurately estimate items due to overflow. Disabling skip list feature for this run.");
                skipListFilePath = ""; // Disable skip list
            }
            else
            {
                // *** ADDED MEMORY CHECK ***
                double fp_rate = 0.01;
                // Calculate m_num_bits *tentatively* based on estimated_items and fp_rate
                double m_exact_check = 0;
                if (estimated_items_in_range > 0)
                { // Avoid division by zero or log(0) issues
                    m_exact_check = -(static_cast<double>(estimated_items_in_range) * std::log(fp_rate)) / (std::log(2.0) * std::log(2.0));
                }
                uint64_t tentative_num_bits = static_cast<uint64_t>(std::ceil(m_exact_check));
                if (tentative_num_bits < 8)
                    tentative_num_bits = 8; // Apply min size

                // Define a reasonable memory limit (e.g., 4GB for the bit vector)
                const uint64_t MAX_FILTER_BITS = 4ULL * 1024 * 1024 * 1024 * 8; // 4 Gigabytes in bits
                // Calculate required MB for logging
                uint64_t required_bytes = (tentative_num_bits + 7) / 8;
                uint64_t required_mb = required_bytes / (1024 * 1024);

                if (tentative_num_bits == 0 || estimated_items_in_range == 0)
                {
                    update_output("WARN: Calculated 0 estimated items or 0 bits needed. Disabling skip list for this run.");
                    skipListFilePath = "";
                }
                else if (tentative_num_bits > MAX_FILTER_BITS)
                {
                    update_output("ERROR: Required Bloom filter size (" + std::to_string(required_mb) + " MB for " + std::to_string(tentative_num_bits) + " bits) exceeds limit (" + std::to_string(MAX_FILTER_BITS / 8 / (1024 * 1024)) + " MB). Disabling skip list.");
                    skipListFilePath = ""; // Disable skip list BEFORE allocation attempt
                }
                else
                {
                    // Proceed with filter creation only if size is acceptable
                    update_output("INFO: Initializing new Bloom filter for approx. " + std::to_string(estimated_items_in_range) + " items with FP rate ~" + std::to_string(fp_rate) + " (Requires ~" + std::to_string(required_mb) + " MB)");
                    try
                    {
                        // Now actually create the filter
                        skipFilter = BloomFilter(estimated_items_in_range, fp_rate);
                        if (skipFilter.isValid())
                        {
                            update_output("INFO: New filter created. Bits: " + std::to_string(skipFilter.getNumBits()) + ", Hashes: " + std::to_string(skipFilter.getNumHashes()));
                        }
                        else
                        {
                            // This branch might be less likely if constructor throws bad_alloc
                            update_output("ERROR: Failed to create a valid Bloom filter after allocation check. Disabling skip list.");
                            skipListFilePath = "";
                        }
                    }
                    catch (const std::bad_alloc &)
                    {
                        update_output("ERROR: Memory allocation failed for Bloom filter (" + std::to_string(required_mb) + " MB requested). Disabling skip list.");
                        skipListFilePath = ""; // Disable on allocation failure
                    }
                    catch (const std::exception &e)
                    {
                        update_output("ERROR: Exception creating Bloom filter: " + std::string(e.what()) + ". Disabling skip list.");
                        skipListFilePath = ""; // Disable on other exceptions
                    }
                    catch (...)
                    {
                        update_output("ERROR: Unknown error creating Bloom filter. Disabling skip list.");
                        skipListFilePath = "";
                    }
                } // End size check block
            } // End overflow check block
        } // End new filter creation block
    }
    else
    {
        update_output("INFO: Skip list feature not requested.");
    }

    // --- Run Brute Force ---
    std::string found_pwd = brute_force_worker_combined(
        charset, min_length, max_length, archivePath, crack_mode,
        skipListFilePath.empty() ? nullptr : &skipFilter,
        skipListFilePath.empty() ? nullptr : &skipFilterMutex,
        checkpointIntervalSeconds,
        pattern
    );

    // --- Report Result to Python ---
    if (!found_pwd.empty()) {
         // Output the special FOUND marker ONLY if found
         std::cout << "FOUND:" << found_pwd << std::endl;
         update_output("INFO: Password found!"); // Log confirmation
         return 0; // Success - Found
    } else {
         // Check if search completed normally or was interrupted (less reliable here)
         // Python GUI determines based on user action vs natural finish.
         update_output("INFO: Password not found within the specified constraints.");
         return 1; // Failure - Not Found (within range)
    }
}