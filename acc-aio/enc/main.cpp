//HOMOMORPHIC EVALUATION OF BINARY DECISION TREE FROM OPENFHE : SERVER SIDE

#include "openfhe.h"

#include <iostream>
#include <filesystem>
#include <string>
#include <cmath>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <ctime>

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

using namespace lbcrypto;
namespace fs = std::filesystem;

const std::string DATAFOLDER = "data";
const std::string RESULTSFOLDER = "results";
const std::string CRYPTOCONTEXT = "cryptocontext";


std::tuple<int, int, int> loadConfigParameters(const std::string& configFile = DATAFOLDER + "/config_params.txt") {
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
                     double deserialize_time, double computation_time, 
                     double serialize_time, double total_time,
                     const std::string& csvFile = "main_timing_results.csv") {
    
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
                << "computation_time,serialize_time,total_time" << std::endl;
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
            << computation_time << ","
            << serialize_time << ","
            << total_time << std::endl;
    
    outFile.close();
    std::cout << "Timing results saved to " << csvFile << std::endl;
}

/////////////////////////////////////////////
//                                         //
//               |MAIN|                    //
//                                         //
/////////////////////////////////////////////

int main()
{
    auto start_total = std::chrono::high_resolution_clock::now();
    
    auto [depth, modulus, security] = loadConfigParameters();
        // 16, 512, 2, 8192, 2, 2, 3)
    int p1 = 16;
    int p2 = 512;
    int p3 = 2;
    int p4 = 8192;
    int p5 = 2;
    int p6 = 2;
    int p7 = 3;

    if (depth == 1) {
        std::cerr << "using default configuration for GPU-1: " 
            << p1 << ", " << p2 << ", " << p3 << ", "
            << p4 << ", " << p5 << ", " << p6 << ", " << p7 << std::endl;

    } else if (depth >= 2 && depth <= 5) {
        p1 = 32;
        p2 = 512;
        p3 = 6;
        p4 = 16384;
        p5 = 2;
        p6 = 6;
        p7 = 7;
        std::cerr << "using configuration for GPU-5: " 
            << p1 << ", " << p2 << ", " << p3 << ", "
            << p4 << ", " << p5 << ", " << p6 << ", " << p7 << std::endl;

    } else if (depth > 5 && depth <= 12) {
        p1 = 64;
        p2 = 512;
        p3 = 25;
        p4 = 32768;
        p5 = 4;
        p6 = 13;
        p7 = 14;
        std::cerr << "using configuration for GPU-12: " 
            << p1 << ", " << p2 << ", " << p3 << ", "
            << p4 << ", " << p5 << ", " << p6 << ", " << p7 << std::endl;
    } else if (depth > 12 && depth <= 24) {
        p1 = 128;
        p2 = 512;
        p3 = 25;
        p4 = 65536;
        p5 = 7;
        p6 = 25;
        p7 = 26;
        std::cerr << "using configuration for GPU-24: " 
            << p1 << ", " << p2 << ", " << p3 << ", "
            << p4 << ", " << p5 << ", " << p6 << ", " << p7 << std::endl;

    } else if (depth > 24 && depth <= 48) {
        p1 = 128;
        p2 = 512;
        p3 = 50;
        p4 = 65536;
        p5 = 12;
        p6 = 49;
        p7 = 50;
        std::cerr << "using configuration for GPU-48: " 
            << p1 << ", " << p2 << ", " << p3 << ", "
            << p4 << ", " << p5 << ", " << p6 << ", " << p7 << std::endl;

    } else {
        std::cerr << "Error: Unsupported depth value. Please use a depth between 1 and 10." 
            << std::endl;
        return 0;

    }

    //getting the depth
    //int depth = calculateDepth(DATAFOLDER);
    //int depth = atoi(argv[1]);
    
    #if defined(WITH_CUDA)
	// Access the singleton instance of cudaDataUtils
	cudaDataUtils& cudaUtils = cudaDataUtils::getInstance();
	// Set GPU configuration - Note: suitable for T4 in AzureVM
	// ringDim = 32768, sizeP = 3, sizeQ = 9, PHatModq_size_y = 10
	cudaUtils.initialize(p1, p2, p3, p4, p5, p6, p7);
	#endif

    auto start_deserialize = std::chrono::high_resolution_clock::now();
    
    //getting the crypto-context and the the public keys
    CryptoContext<DCRTPoly> cc;

    if (!Serial::DeserializeFromFile(CRYPTOCONTEXT + "/cryptocontext.txt", cc, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from " << CRYPTOCONTEXT + "/cryptocontext.txt" << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been deserialized." << std::endl;

    PublicKey<DCRTPoly> pk;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk, SerType::BINARY) == false) {
        std::cerr << "Could not read public key" << std::endl;
        return 1;
    }
    std::cout << "The public key has been deserialized." << std::endl;
    
    std::ifstream emkeys(DATAFOLDER + "/key-eval-mult.txt", std::ios::in | std::ios::binary);
    if (!emkeys.is_open()) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-mult.txt" << std::endl;
        return 1;
    }
    if (cc->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the eval mult key file" << std::endl;
        return 1;
    }
    std::cout << "Deserialized the eval mult keys." << std::endl;
    
	Ciphertext<DCRTPoly> ciphertext1;

	if (Serial::DeserializeFromFile(DATAFOLDER + "/" + "enc_file1.txt", ciphertext1, SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
    }
    std::cout << "a ciphertext has been deserialized." << std::endl;

    Ciphertext<DCRTPoly> ciphertext2;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/" + "enc_file2.txt", ciphertext2, SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
    }
    
    auto end_deserialize = std::chrono::high_resolution_clock::now();
    
    // Time homomorphic computation
    auto start_computation = std::chrono::high_resolution_clock::now();
    
    auto ciphertextMultResult = ciphertext1;
    for (int i = 0; i < depth; i++) {
        ciphertextMultResult = cc->EvalMult(ciphertextMultResult, ciphertext2);
    }
    
    auto end_computation = std::chrono::high_resolution_clock::now();
    
    // Time serialization
    auto start_serialize = std::chrono::high_resolution_clock::now();
    
    //serializing the final result
    if (!Serial::SerializeToFile(RESULTSFOLDER + "/" + "output_ciphertext.txt", ciphertextMultResult, SerType::BINARY)) {
        std::cerr << "Error writing serialization of output ciphertext to output_ciphertext.txt" << std::endl;
        return 1;
    }
    std::cout << "The output ciphertext has been serialized." << std::endl;
    
    auto end_serialize = std::chrono::high_resolution_clock::now();
    auto end_total = std::chrono::high_resolution_clock::now();
    
    // Calculate durations in microseconds
    auto deserialize_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_deserialize - start_deserialize);
    auto computation_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_computation - start_computation);
    auto serialize_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_serialize - start_serialize);
    auto total_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_total - start_total);

    // Convert to seconds
    double deserialize_time = deserialize_duration.count() / 1000000.0;
    double computation_time = computation_duration.count() / 1000000.0;
    double serialize_time = serialize_duration.count() / 1000000.0;
    double total_time = total_duration.count() / 1000000.0;

    // Output timing results in a parseable format
    std::cout << "=== TIMING_RESULTS ===" << std::endl;
    std::cout << "MAIN_DESERIALIZE_TIME: " << deserialize_time << std::endl;
    std::cout << "MAIN_COMPUTATION_TIME: " << computation_time << std::endl;
    std::cout << "MAIN_SERIALIZE_TIME: " << serialize_time << std::endl;
    std::cout << "MAIN_TOTAL_TIME: " << total_time << std::endl;
    
    // Save to CSV
    saveTimingToCSV("computation", depth, modulus, security,
                    deserialize_time, computation_time, serialize_time, total_time);
    
    //////////////////////////////
    //////////////////////////////
      
    //main return value
    return 0;
}
