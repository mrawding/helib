
#include <iostream>
#include <helib/helib.h>
#include <helib/replicate.h>
#include <helib/keySwitching.h>
#include <string.h>
#include <chrono>


/*  Example of BGV scheme  */
int main(int argc, char *argv[]) {

    long p = 1021;      // Plaintext prime modulus
    long r = 1;         // Hensel lifting (default = 1)
    int bits = 250;    // Number of bits of the modulus chain
    long c = 2;         // Number of columns of Key-Switching matix (default = 2 or 3)
    long k = 128;       // Security level
    long s = 1;         // Minimum number of plaintext slots
    long d = 1;         // Embedding degree
    long w = 64;        // hamming weight of secret key
    long m = 18907;      // Cyclotomic polynomial - defines phi(m)

    std::cout << "Initialising context object..." << std::endl;
    // Intialise context
    helib::Context context(m, p, r);
    // Modify the context, adding primes to the modulus chain
    std::cout  << "Building modulus chain..." << std::endl;
    buildModChain(context, bits, c);

    // Print the context
    context.zMStar.printout();
    std::cout << std::endl;

    // Print the security level
    std::cout << "Security: " << context.securityLevel() << std::endl;

    // Secret key management
    std::cout << "Creating secret key..." << std::endl;
    // Create a secret key associated with the context
    helib::SecKey secret_key(context);
    // Generate the secret key
    secret_key.GenSecKey();
    std::cout << "Generating key-switching matrices..." << std::endl;
    // Compute key-switching matrices that we need
    helib::addSome1DMatrices(secret_key);
    // Public key management
    // Set the secret key (upcast: SecKey is a subclass of PubKey)
    const helib::PubKey& public_key = secret_key;

    // Get the EncryptedArray of the context
    const helib::EncryptedArray& ea = *(context.ea);

    // Get the number of slot (phi(m))
    long nslots = ea.size();
    std::cout << "Number of slots: " << nslots << std::endl;

    // Create a vector of long with nslots elements
    std::vector<long> ptxt(nslots);
    // Set it with numbers 0..nslots - 1

    for (int i = 0; i < 10; ++i) {
        ptxt[i] = i;
    }

    std::cout << std::endl;
    std::cout << "Plaintext: " << helib::vecToStr(std::vector<int>(ptxt.begin(), ptxt.begin()+10)) << std::endl;
    std::cout << std::endl;
    // Create a ciphertext
    helib::Ctxt ctxt(public_key);

    // Encrypt the plaintext using the public_key
    ea.encrypt(ctxt, public_key, ptxt);
    //std::cout << "Here's what a ciphertext looks like: " << ctxt << std::endl;
    // Multiply ctxt by itself
    std::cout << "Computing ctxt^2 homomorphically..." << std::endl;
    auto t1 = std::chrono::high_resolution_clock::now();
    ctxt.multiplyBy(ctxt);
    auto t2 = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>( t2 - t1 ).count();

    // Decrypt ctxt^2
    std::vector<long> decrypted_square(nslots);
    ea.decrypt(ctxt, secret_key, decrypted_square);
    std::cout << "Mult time: " << duration << std::endl;
    std::cout << "Decrypted Square: " << helib::vecToStr(std::vector<int>(decrypted_square.begin(), decrypted_square.begin()+10)) << std::endl;
    std::cout << std::endl;


    // Add ctxt to itself
    std::cout << "Computing ctxt^2 + ctxt^2 homomorphically..." << std::endl;
    t1 = std::chrono::high_resolution_clock::now();
    ctxt += ctxt;
    t2 = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>( t2 - t1 ).count();

    // Decrypt ctxt^2 + ctxt^2
    std::vector<long> decrypted_sum(nslots);
    ea.decrypt(ctxt, secret_key, decrypted_sum);
    std::cout << "Add time: " << duration << std::endl;
    std::cout << "Decrypted Sum: " << helib::vecToStr(std::vector<int>(decrypted_sum.begin(), decrypted_sum.begin()+10)) << std::endl;
    std::cout << std::endl;

    // Subtract ctxt by itself
    std::cout << "Computing 2*ctxt^2 - 2*ctxt^2 homomorphically..." << std::endl;
    t1 = std::chrono::high_resolution_clock::now();
    ctxt -= ctxt;
    t2 = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>( t2 - t1 ).count();

    // Decrypt 2*ctxt^2 - ctxt^2
    std::vector<long> decrypted_sub(nslots);
    ea.decrypt(ctxt, secret_key, decrypted_sub);
    std::cout << "Sub time: " << duration << std::endl;
    std::cout << "Decrypted Sub: " << helib::vecToStr(std::vector<int>(decrypted_sub.begin(), decrypted_sub.begin()+10)) << std::endl;
    std::cout << std::endl;

    // Consume all of the noise budget

    // Create a vector of long with nslots elements
    std::vector<long> ptxt_2(nslots);
    // Set it with numbers 0..nslots - 1

    for (int i = 0; i < 10; ++i) {
        ptxt[i] = 10-i;
    }

    std::cout << std::endl;
    std::cout << "What happens when I try to do too many operations? Like 10 multiplications." << std::endl;
    std::cout << "Plaintext 2: " << helib::vecToStr(std::vector<int>(ptxt.begin(), ptxt.begin()+10)) << std::endl;
    std::cout << std::endl;
    // Create a ciphertext
    helib::Ctxt ctxt_2(public_key);

    // Encrypt the plaintext using the public_key
    ea.encrypt(ctxt_2, public_key, ptxt_2);
    for(int i = 0; i < 10; i++) {
      ctxt_2.multiplyBy(ctxt_2);
    }

    std::vector<long> decrypted_fail(nslots);
    ea.decrypt(ctxt_2, secret_key, decrypted_fail);
    std::cout << "**AS EXPECTED** Decryption Fail: " << helib::vecToStr(std::vector<int>(decrypted_fail.begin(), decrypted_fail.begin()+10)) << std::endl;
    std::cout << std::endl;


    return EXIT_SUCCESS;
}
