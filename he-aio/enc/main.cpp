//HOMOMORPHIC EVALUATION OF BINARY DECISION TREE FROM OPENFHE : SERVER SIDE

#include "openfhe.h"

#include <iostream>
#include <filesystem>
#include <string>
#include <cmath>

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



//binary decision trees

/////////////////////////////////////////////
//                                         //
//               |MAIN|                    //
//                                         //
/////////////////////////////////////////////

int main()
{
    auto [depth, modulus, security] = loadConfigParameters();
	
    //getting the depth
	//int depth = calculateDepth(DATAFOLDER);
	//int depth = atoi(argv[1]);
	
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

    auto ciphertextMultResult = ciphertext1;
    for (int i = 0; i < depth; i++) {
        ciphertextMultResult = cc->EvalMult(ciphertextMultResult, ciphertext2);
    }
	//serializing the final result
	if (!Serial::SerializeToFile(RESULTSFOLDER + "/" + "output_ciphertext.txt", ciphertextMultResult, SerType::BINARY)) {
        std::cerr << "Error writing serialization of output ciphertext to output_ciphertext.txt" << std::endl;
        return 1;
    }
    std::cout << "The output ciphertext has been serialized." << std::endl;
    
    //////////////////////////////
    //////////////////////////////
      
    //main return value
    return 0;
}
