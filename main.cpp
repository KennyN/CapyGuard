#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <filesystem>
#include <string>
#include <thread>  // Include this for sleep_for
#include <iomanip>  // For std::setw, std::setfill
#include <sstream>  // For std::ostringstream
#include <nlohmann/json.hpp>
#include "malwarebazaar.hpp"

std::string importFile(const std::string& filePath);
std::string calculateSHA256(const std::string& filePath);
nlohmann::json loadJsonFile(const std::string& jsonFilePath);
void saveJsonFile(const std::string& jsonFilePath, const nlohmann::json& jsonData);
std::string getLastModifiedTime(const std::string& filePath);
std::string getCurrentTime();

int main() {
    // Load Json File
    std::string jsonFilePath = "./fim_data.json";
    nlohmann::json fileData = loadJsonFile(jsonFilePath);

    // Tracking new hashes submitted to MalwareBazaar
    

    // Iterate through each file entry in the JSON and print details
    for (const auto& file : fileData["files"]) {
        std::string fileName = file["name"];
        std::string filePath = file["path"];
        std::string baselineHash = file["baseline_hash"];
        std::string currentHash = file["current_hash"];
        std::string lastModified = file["last_modified"];

        std::cout << "File: " << fileName << std::endl;
        std::cout << "Path: " << filePath << std::endl;
        std::cout << "Baseline Hash: " << baselineHash << std::endl;
        std::cout << "Current Hash: " << currentHash << std::endl;
        std::cout << "Last Modified: " << lastModified << std::endl;
        std::cout << std::endl;
    }

    // Check current hash of all files
    while (true) {
        for (auto& file: fileData["files"]) {
            std::string currentHash = calculateSHA256(file["path"]);
            std::string currentTime = getCurrentTime();
            
            if (!currentHash.empty()) {

                file["current_hash"] = currentHash;
                std::cout << "Current Hash of " << file["name"] << " is: " << currentHash << std::endl;
                
                if (currentHash != file["baseline_hash"]) { // Check to see if the current hash is different from baseline
                    std::cout << "["<< currentTime << "] " << "\033[31m[WARNING]\033[0m Potential Tampering - Hash change from: " << file["baseline_hash"] << " -> " << currentHash << std::endl;
                    std::cout << "\033[33mSending hash to MalwareBazaar...\033[0m" << std::endl;
                    check_malwarebazaar(file["current_hash"]);
                    std::string lastModified = getLastModifiedTime(file["path"]);
                    file["last_modified"] = lastModified;
                }

            } else {
                // FILE IS NO LONGER HERE. DELETION OR MOVEMENT.
                file["current_hash"] = "REMOVED";
                std::cerr << "["<< currentTime << "] " << "\033[31m[WARNING]\033[0m Deletion/Movement - Could not locate file:  " << file["name"] << " at " << file["path"] << std::endl;
            }

            saveJsonFile(jsonFilePath, fileData);
        }

        // Add a 1-second delay between iterations
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    /*
    std::string filePath = "./testfile.txt";  // Replace with the path to your file
    std::string fileContent = importFile(filePath);

    if (!fileContent.empty()) {
        std::cout << "File content:\n" << fileContent << std::endl;
    }
    std::string hashValue = calculateSHA256(filePath);
    std::cout << "SHA256 Hash:\n" << hashValue << std::endl;
    std::cout << "Comparing hash to MalwareBazaar:" << std::endl;
    check_malwarebazaar("hashValue");
    return 0;
    */
}


// LOAD IN FIM_DATA JSON
nlohmann::json loadJsonFile(const std::string& jsonFilePath) {
    std::ifstream inFile(jsonFilePath);
    nlohmann::json jsonData;

    if (inFile.is_open()) {
        inFile >> jsonData;
        inFile.close();
    } else {
        std::cerr << "Error: Could not open JSON file " << jsonFilePath << std::endl;
    }

    return jsonData;
}

// Function to save JSON data to a file
void saveJsonFile(const std::string& jsonFilePath, const nlohmann::json& jsonData) {
    std::ofstream outFile(jsonFilePath);
    if (outFile.is_open()) {
        outFile << std::setw(4) << jsonData << std::endl;  // Pretty print with indentation
        outFile.close();
    } else {
        std::cerr << "Error: Could not open JSON file for writing " << jsonFilePath << std::endl;
    }
}

std::string importFile(const std::string& filePath) {
    std::ifstream file(filePath);  // Create an ifstream object to open the file
    if (!file.is_open()) {  // Check if the file was successfully opened
        std::cerr << "Error: Could not open file " << filePath << std::endl;
        return "";  // Return an empty string if the file can't be opened
    }

    std::string content;
    std::string line;
    while (std::getline(file, line)) {  // Read the file line by line
        content += line + '\n';  // Add each line to the content string
    }

    file.close();  // Close the file after reading it
    return content;  // Return the content of the file
}

// Function to get the last modified time of a file
std::string getLastModifiedTime(const std::string& filePath) {
    std::filesystem::file_time_type ftime = std::filesystem::last_write_time(filePath);
    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(ftime - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
    std::time_t cftime = std::chrono::system_clock::to_time_t(sctp);

    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&cftime), "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::string calculateSHA256(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file " << filePath << std::endl;
        return "";
    }

    // Check if the file is empty
    file.seekg(0, std::ios::end);
    std::streampos fileSize = file.tellg();
    if (fileSize == 0) {
        std::cerr << "Error: File " << filePath << " is empty." << std::endl;
        return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";  // Hash for an empty file
    }
    file.seekg(0, std::ios::beg);  // Reset to the beginning of the file

    // Create and initialize the EVP context
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context) {
        std::cerr << "Error: Could not create EVP_MD_CTX" << std::endl;
        return "";
    }

    // Initialize the digest context for SHA-256
    if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
        std::cerr << "Error: Could not initialize digest context" << std::endl;
        EVP_MD_CTX_free(context);
        return "";
    }

    // Read the file in chunks and update the hash
    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        if (EVP_DigestUpdate(context, buffer, file.gcount()) != 1) {
            std::cerr << "Error: Could not update digest" << std::endl;
            EVP_MD_CTX_free(context);
            return "";
        }
    }

    // Finalize the digest
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    if (EVP_DigestFinal_ex(context, hash, &lengthOfHash) != 1) {
        std::cerr << "Error: Could not finalize digest" << std::endl;
        EVP_MD_CTX_free(context);
        return "";
    }

    // Clean up the context
    EVP_MD_CTX_free(context);

    // Convert the hash to a hex string
    std::ostringstream oss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return oss.str();
}

// Function to get the current time as a string
std::string getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);

    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&now_c), "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

