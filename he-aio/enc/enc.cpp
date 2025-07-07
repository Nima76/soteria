//HOMOMORPHIC EVALUATION OF BINARY DECISION TREE FROM OPENFHE : CLIENT SIDE

#include "openfhe.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <stdexcept>
#include <chrono>

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

using namespace lbcrypto;

const std::string DATAFOLDER = "tee_data";
const std::string PRIVATEKEY = "private_data";
const std::string RESULTSFOLDER = "data";
const std::string CRYPTOCONTEXT = "cryptocontext";


void saveConfigParameters(int multDepth, int plainModulus, int securityLevel, const std::string& configFile = RESULTSFOLDER + "/config_params.txt") {
    std::ofstream outFile(configFile);
    if (!outFile.is_open()) {
        std::cerr << "Error: Could not open configuration file for writing: " << configFile << std::endl;
        return;
    }
    
    outFile << "depth=" << multDepth << std::endl;
    outFile << "modulus=" << plainModulus << std::endl;
    outFile << "security=" << securityLevel << std::endl;
    
    outFile.close();
    std::cout << "Configuration parameters saved to " << configFile << std::endl;
}


void saveTimingToCSV(const std::string& phase, 
                     uint32_t depth, uint32_t modulus, uint32_t security,
                     double context_time, double keygen_time, 
                     double encrypt_time, double serialize_time, 
                     double total_time,
                     const std::string& csvFile = "enc_timing_results.csv") {
    
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
        outFile << "timestamp,phase,depth,modulus,security,context_time,keygen_time,"
                << "encrypt_time,serialize_time,total_time" << std::endl;
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
            << std::fixed << std::setprecision(10) << context_time << ","
            << keygen_time << ","
            << encrypt_time << ","
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


int main(int argc, char* argv[])
{
    auto start_total = std::chrono::high_resolution_clock::now();

    //cryptocontext setting
    uint32_t multDepth = 1;
    uint32_t plainModulus = 65537;
    uint32_t securityLevel = 128; // Default security level
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--depth" && i + 1 < argc) {
            multDepth = std::stoi(argv[++i]);
        } else if (arg == "--modulus" && i + 1 < argc) {
            plainModulus = std::stoi(argv[++i]);
        } else if (arg == "--security" && i + 1 < argc) {
            securityLevel = std::stoi(argv[++i]);
            if (securityLevel != 128 && securityLevel != 192 && securityLevel != 256) {
                std::cout << "Warning: Security level must be 128, 192, or 256. Setting to default (128)." << std::endl;
                securityLevel = 128;
            }
        } else if (arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [OPTIONS]\n"
                      << "Options:\n"
                      << "  --depth N       Set multiplicative depth (default: 8)\n"
                      << "  --modulus N     Set plaintext modulus (default: 65537)\n"
                      << "  --security N    Set security level (128, 192, or 256) (default: 128)\n"
                      << "  --help          Display this help message\n";
            return 0;
        }
    }
    
    // Time context creation
    auto start_context = std::chrono::high_resolution_clock::now();
    
    //cryptocontext setting
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetPlaintextModulus(plainModulus);
    SecurityLevel secLevelEnum;
    if (securityLevel == 128) {
        secLevelEnum = HEStd_128_classic;
    } else if (securityLevel == 192) {
        secLevelEnum = HEStd_192_classic;
    } else if (securityLevel == 256) {
        secLevelEnum = HEStd_256_classic;
    } else {
        std::cout << "Warning: Invalid security level. Defaulting to 128-bit." << std::endl;
        secLevelEnum = HEStd_128_classic;
    }
    parameters.SetSecurityLevel(secLevelEnum);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    
    auto end_context = std::chrono::high_resolution_clock::now();
    
    // Time key generation
    auto start_keygen = std::chrono::high_resolution_clock::now();
    
    //key generation
    KeyPair<DCRTPoly> keyPair;
    keyPair = cc->KeyGen();
    const PublicKey<DCRTPoly> pk = keyPair.publicKey;
    const PrivateKey<DCRTPoly> sk = keyPair.secretKey;
    
    cc->EvalMultKeyGen(sk);
    
    auto end_keygen = std::chrono::high_resolution_clock::now();
    
    // Time plaintext creation and encryption
    auto start_encrypt = std::chrono::high_resolution_clock::now();
    
    std::vector<int64_t> vectorOfInts1 = {1,1,1,1};
    Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

    std::vector<int64_t> vectorOfInts2 = {1,1,1,1};
    Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

    std::cout << "Decision tree succesfully built from the input file." << std::endl;

    auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);
    
    auto end_encrypt = std::chrono::high_resolution_clock::now();
    
    // Time serialization
    auto start_serialize = std::chrono::high_resolution_clock::now();
    
    // Serialize cryptocontext
    if (!Serial::SerializeToFile(CRYPTOCONTEXT + "/cryptocontext.txt", cc, SerType::BINARY)) {
        std::cerr << "Error writing serialization of the crypto context to "
                     "cryptocontext.txt"
                  << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been serialized." << std::endl;
    
    // Serialize the public key
    if (!Serial::SerializeToFile(RESULTSFOLDER + "/key-public.txt", keyPair.publicKey, SerType::BINARY)) {
        std::cerr << "Error writing serialization of private key to key-public.txt" << std::endl;
        return 1;
    }
    std::cout << "The public key has been serialized." << std::endl;
    
    // Serialize the secret key
    if (!Serial::SerializeToFile(PRIVATEKEY + "/key-private.txt", keyPair.secretKey, SerType::BINARY)) {
        std::cerr << "Error writing serialization of private key to key-private.txt" << std::endl;
        return 1;
    }
    std::cout << "The secret key has been serialized." << std::endl;
    
    // Serialize the relinearization (evaluation) key for homomorphic
    // multiplication
    std::ofstream emkeyfile(RESULTSFOLDER + "/" + "key-eval-mult.txt", std::ios::out | std::ios::binary);
    if (emkeyfile.is_open()) {
        if (cc->SerializeEvalMultKey(emkeyfile, SerType::BINARY) == false) {
            std::cerr << "Error writing serialization of the eval mult keys to "
                         "key-eval-mult.txt"
                      << std::endl;
            return 1;
        }
        std::cout << "The eval mult keys have been serialized." << std::endl;

        emkeyfile.close();
    }
    else {
        std::cerr << "Error serializing eval mult keys" << std::endl;
        return 1;
    }
    
    if (!Serial::SerializeToFile(RESULTSFOLDER + "/enc_file1.txt", ciphertext1, SerType::BINARY)) {
      std::cerr << "Error writing serialization of ciphertext1  to enc_file1.txt" << std::endl;
      return 1;
    }
    if (!Serial::SerializeToFile(RESULTSFOLDER + "/enc_file2.txt", ciphertext2, SerType::BINARY)) {
      std::cerr << "Error writing serialization of ciphertext2  to enc_file2.txt" << std::endl;
      return 1;
    }
    
    saveConfigParameters(multDepth, plainModulus, securityLevel);
    
    auto end_serialize = std::chrono::high_resolution_clock::now();
    auto end_total = std::chrono::high_resolution_clock::now();

    // Calculate durations in microseconds
    auto context_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_context - start_context);
    auto keygen_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_keygen - start_keygen);
    auto encrypt_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_encrypt - start_encrypt);
    auto serialize_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_serialize - start_serialize);
    auto total_duration = std::chrono::duration_cast<std::chrono::microseconds>(end_total - start_total);

    // Convert to seconds
    double context_time = context_duration.count() / 1000000.0;
    double keygen_time = keygen_duration.count() / 1000000.0;
    double encrypt_time = encrypt_duration.count() / 1000000.0;
    double serialize_time = serialize_duration.count() / 1000000.0;
    double total_time = total_duration.count() / 1000000.0;

    // Output timing results in a parseable format
    std::cout << "=== TIMING_RESULTS ===" << std::endl;
    std::cout << "ENC_CONTEXT_TIME: " << context_time << std::endl;
    std::cout << "ENC_KEYGEN_TIME: " << keygen_time << std::endl;
    std::cout << "ENC_ENCRYPT_TIME: " << encrypt_time << std::endl;
    std::cout << "ENC_SERIALIZE_TIME: " << serialize_time << std::endl;
    std::cout << "ENC_TOTAL_TIME: " << total_time << std::endl;

    saveTimingToCSV("encryption", multDepth, plainModulus, securityLevel,
                    context_time, keygen_time, encrypt_time, serialize_time, total_time);

    
    return 0;
}