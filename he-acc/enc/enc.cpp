//HOMOMORPHIC EVALUATION OF BINARY DECISION TREE FROM OPENFHE : CLIENT SIDE

#include "openfhe.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <stdexcept>

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

/////////////////////////////////////////////
//                                         //
//               |MAIN|                    //
//                                         //
/////////////////////////////////////////////


int main(int argc, char* argv[])
{

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


      //parameters.SetMultiplicativeDepth(1);
      //parameters.SetPlaintextModulus(65537);

      CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

      cc->Enable(PKE);
      cc->Enable(KEYSWITCH);
      cc->Enable(LEVELEDSHE);
      
      //key generation
      KeyPair<DCRTPoly> keyPair;
      keyPair = cc->KeyGen();
      const PublicKey<DCRTPoly> pk = keyPair.publicKey;
      const PrivateKey<DCRTPoly> sk = keyPair.secretKey;
      
      cc->EvalMultKeyGen(sk);
      

      
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
      


        std::vector<int64_t> vectorOfInts1 = {1,1,1,1};
        Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

        std::vector<int64_t> vectorOfInts2 = {1,1,1,1};
        Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

        std::cout << "Decision tree succesfully built from the input file." << std::endl;

        // Nettoyage de la mémoire (supprimer les sous-arbres)
        // Ajoutez une fonction `freeTree` si nécessaire pour libérer les enfants dynamiques

      auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
      auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);
      
      if (!Serial::SerializeToFile(RESULTSFOLDER + "/enc_file1.txt", ciphertext1, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext1  to enc_file1.txt" << std::endl;
        return 1;
    }
    if (!Serial::SerializeToFile(RESULTSFOLDER + "/enc_file2.txt", ciphertext2, SerType::BINARY)) {
      std::cerr << "Error writing serialization of ciphertext2  to enc_file2.txt" << std::endl;
      return 1;
  }
    saveConfigParameters(multDepth, plainModulus, securityLevel);
    return 0;
}