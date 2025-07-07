//HOMOMORPHIC EVALUATION OF BINARY DECISION TREE FROM OPENFHE : RESULT DECRYPTION

#include "openfhe.h"

#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <sstream>

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

using namespace lbcrypto;

const std::string DATAFOLDER = "results";
const std::string RESULTSFOLDER = "dec_results";
const std::string CRYPTOCONTEXT = "cryptocontext";
const std::string PRIVATEKEY = "private_data";

std::tuple<int, int, int> loadConfigParameters(const std::string& configFile = "data/config_params.txt") {
    std::ifstream inFile(configFile);
    if (!inFile.is_open()) {
        std::cerr << "Error: Could not open configuration file for reading: " << configFile << std::endl;
        return {8, 65537, 128}; // Return default values
    }
    
    int depth = 8;      // Default value
    int modulus = 65537; // Default value
    int security = 128;  // Default value
    
    std::string line;
    while (std::getline(inFile, line)) {
        std::istringstream iss(line);
        std::string key;
        std::getline(iss, key, '=');
        
        if (key == "depth") {
            iss >> depth;
        } else if (key == "modulus") {
            iss >> modulus;
        } else if (key == "security") {
            iss >> security;
        }
    }
    
    inFile.close();
    return {depth, modulus, security};
}

void saveTimingToCSV(const std::string& phase, 
                     int depth, int modulus, int security,
                     double deserialize_time, double decrypt_time, 
                     double save_time, double total_time,
                     const std::string& csvFile = "dec_timing_results.csv") {
    
    // Check if file exists to determine if we need to write headers
    bool fileExists = false;
    std::ifstream checkFile(csvFile);
    if (checkFile.good()) {
        fileExists = true;
    }
    checkFile.close();
    
    // Open file in append mode
    std::ofstream outFile(csvFile, std::ios::app);
    if (!outFile.is_open()) {
        std::cerr << "Error: Could not open CSV file for writing: " << csvFile << std::endl;
        return;
    }
    
    // Write headers if file is new
    if (!fileExists) {
        outFile << "timestamp,phase,depth,modulus,security,deserialize_time,"
                << "decrypt_time,save_time,total_time" << std::endl;
    }
    
    // Get current timestamp
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    // Write data row
    outFile << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << ","
            << phase << ","
            << depth << ","
            << modulus << ","
            << security << ","
            << std::fixed << std::setprecision(10) << deserialize_time << ","
            << decrypt_time << ","
            << save_time << ","
            << total_time << std::endl;
    
    outFile.close();
    std::cout << "Timing results saved to " << csvFile << std::endl;
}

int main()
{
    auto start_total = std::chrono::high_resolution_clock::now();
    
    // Load configuration parameters
    auto [depth, modulus, security] = loadConfigParameters();
    
    // Time deserialization
    auto start_deserialize = std::chrono::high_resolution_clock::now();
    
    //getting the crypto-context
    CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile(CRYPTOCONTEXT + "/cryptocontext.txt", cc, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from " << CRYPTOCONTEXT + "/cryptocontext.txt" << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been deserialized." << std::endl;
    
    //getting the secret key
    PrivateKey<DCRTPoly> sk;
    if (Serial::DeserializeFromFile(PRIVATEKEY + "/key-private.txt", sk, SerType::BINARY) == false) {
        std::cerr << "Could not read secret key" << std::endl;
        return 1;
    }
    std::cout << "The secret key has been deserialized." << std::endl;
    
    //getting the encrypted result
    Ciphertext<DCRTPoly> output_ciphertext;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/output_ciphertext.txt", output_ciphertext, SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
        return 1;
    }
    std::cout << "The encrypted result of the homomorphic evaluation has been deserialized." << std::endl;
    
    auto end_deserialize = std::chrono::high_resolution_clock::now();
    
    // Time decryption
    auto start_decrypt = std::chrono::high_resolution_clock::now();
    
    //decrypting the result
    Plaintext final_output;
    cc->Decrypt(sk, output_ciphertext, &final_output);
    std::cout << "OUTPUT VALUE : " << final_output << std::endl;
    
    auto end_decrypt = std::chrono::high_resolution_clock::now();
    
    // Time saving result
    auto start_save = std::chrono::high_resolution_clock::now();
    
    //saving the decrypted result
    std::string filepath = "dec_results/result.txt";
    std::ofstream outfile(filepath);
    if (!outfile) {
       std::cout << "Could not open the target file for saving the decrypted result" << std::endl;
       return 1; 
    }
    outfile << final_output << std::endl;
    outfile.close();
    
    auto end_save = std::chrono::high_resolution_clock::now();
    auto end_total = std::chrono::high_resolution_clock::now();
    
    // Calculate durations in microseconds
    auto deserialize_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_deserialize - start_deserialize);
    auto decrypt_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_decrypt - start_decrypt);
    auto save_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_save - start_save);
    auto total_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_total - start_total);

    // Convert to seconds
    double deserialize_time = deserialize_duration.count() / 1000000.0;
    double decrypt_time = decrypt_duration.count() / 1000000.0;
    double save_time = save_duration.count() / 1000000.0;
    double total_time = total_duration.count() / 1000000.0;

    // Output timing results in a parseable format
    std::cout << "=== TIMING_RESULTS ===" << std::endl;
    std::cout << "DEC_DESERIALIZE_TIME: " << deserialize_time << std::endl;
    std::cout << "DEC_DECRYPT_TIME: " << decrypt_time << std::endl;
    std::cout << "DEC_SAVE_TIME: " << save_time << std::endl;
    std::cout << "DEC_TOTAL_TIME: " << total_time << std::endl;
    
    // Save to CSV
    saveTimingToCSV("decryption", depth, modulus, security,
                    deserialize_time, decrypt_time, save_time, total_time);
    
    //main return value
    return 0;
}