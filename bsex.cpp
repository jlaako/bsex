/*

    bsex - Botan based stream cipher utility for backup encryption
    Copyright (C) 2018 Jussi Laako

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions, and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions, and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.

*/


#include <cstdio>
#include <exception>
#include <string>
#include <vector>
#include <memory>
#include <iostream>
#include <fstream>

#include <botan/version.h>
#include <botan/init.h>
#include <botan/types.h>
#include <botan/secmem.h>
#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/ed25519.h>
#include <botan/x509_key.h>
#include <botan/x509_obj.h>
#include <botan/pkcs8.h>
#include <botan/ctr.h>


static void keygen (const std::string &baseName)
{
    Botan::AutoSeeded_RNG PRNG;

    Botan::RSA_PrivateKey KeyPairRSA(PRNG, 4096);
    if (!KeyPairRSA.check_key(PRNG, true))
        throw std::domain_error("RSA key check failed");
    // we don't truncate on purpose to avoid accidentally overwriting keys
    std::ofstream PubFileRSA(baseName + "_pub_rsa.pem",
        std::ios_base::out | std::ios_base::binary);
    std::ofstream PrivFileRSA(baseName + "_priv_rsa.pem",
        std::ios_base::out | std::ios_base::binary);
    PubFileRSA << Botan::X509::PEM_encode(KeyPairRSA);
    PrivFileRSA << Botan::PKCS8::PEM_encode(KeyPairRSA);

    Botan::Ed25519_PrivateKey KeyPairEd25519(PRNG);
    if (!KeyPairEd25519.check_key(PRNG, true))
        throw std::domain_error("Ed25519 key check failed");
    // we don't truncate on purpose to avoid accidentally overwriting keys
    std::ofstream PubFileEd25519(baseName + "_pub_ed25519.pem",
        std::ios_base::out | std::ios_base::binary);
    std::ofstream PrivFileEd25519(baseName + "_priv_ed25519.pem",
        std::ios_base::out | std::ios_base::binary);
    PubFileEd25519 << Botan::X509::PEM_encode(KeyPairEd25519);
    PrivFileEd25519 << Botan::PKCS8::PEM_encode(KeyPairEd25519);
}


static void encrypt (const std::string &signBaseName,
    const std::string &wrapBaseName, std::ostream &fileOut)
{
    Botan::AutoSeeded_RNG PRNG;

    std::unique_ptr<Botan::Private_Key> SignKey(
        Botan::PKCS8::load_key(signBaseName + "_priv_ed25519.pem", PRNG));
    std::unique_ptr<Botan::Public_Key> WrapKey(
        Botan::X509::load_key(wrapBaseName + "_pub_rsa.pem"));

    std::unique_ptr<Botan::StreamCipher> SymCipher(
        Botan::CTR_BE::create_or_throw("CTR(AES-256)"));
    Botan::secure_vector<uint8_t> SymKey(
        PRNG.random_vec(SymCipher->maximum_keylength()));
    Botan::secure_vector<uint8_t> SymIV(
        PRNG.random_vec(SymCipher->default_iv_length()));

    fprintf(stderr, "keysize=%lu, ivsize=%lu\n", SymKey.size(), SymIV.size());
    SymCipher->set_key(SymKey);
    SymCipher->set_iv(SymIV.data(), SymIV.size());

    uint32_t u32WrappedSize;
    Botan::PK_Encryptor_EME WrapEncryptor(*WrapKey.get(), PRNG, "EME1(SHA-256)");
    std::vector<uint8_t> WrappedKey(WrapEncryptor.encrypt(SymKey, PRNG));
    std::vector<uint8_t> WrappedIV(WrapEncryptor.encrypt(SymIV, PRNG));
    // wrapped key
    u32WrappedSize = static_cast<uint32_t> (WrappedKey.size());
    fileOut.write(reinterpret_cast<char *> (&u32WrappedSize), sizeof(u32WrappedSize));
    if (!fileOut.good())
        throw std::range_error("failed to write wrapped key size");
    fileOut.write(reinterpret_cast<char *> (WrappedKey.data()), WrappedKey.size());
    if (!fileOut.good())
        throw std::range_error("failed to write wrapped key");
    // wrapped IV
    u32WrappedSize = static_cast<uint32_t> (WrappedIV.size());
    fileOut.write(reinterpret_cast<char *> (&u32WrappedSize), sizeof(u32WrappedSize));
    if (!fileOut.good())
        throw std::range_error("failed to write wrapped iv size");
    fileOut.write(reinterpret_cast<char *> (WrappedIV.data()), WrappedIV.size());
    if (!fileOut.good())
        throw std::range_error("failed to write wrapped iv");

    uint32_t u32SigSize;
    size_t sizeSigPos = fileOut.tellp();
    Botan::PK_Signer Signer(*SignKey.get(), PRNG, "SHA-512");
    u32SigSize = Signer.signature_length();
    std::vector<uint8_t> Signature(u32SigSize);
    fprintf(stderr, "sigpos=%lu, sigsize=%u\n", sizeSigPos, u32SigSize);
    // signature placeholder
    fileOut.write(reinterpret_cast<char *> (&u32SigSize), sizeof(u32SigSize));
    if (!fileOut.good())
        throw std::range_error("failed to write signature size");
    fileOut.write(reinterpret_cast<char *> (Signature.data()), Signature.size());
    if (!fileOut.good())
        throw std::range_error("failed to write signature");

    const size_t sizeBlock = 1048576 * 4;  // 4 MiB
    Botan::secure_vector<uint8_t> CipherBlock(sizeBlock);

    while (std::cin.good())
    {
        std::cin.read(reinterpret_cast<char *> (CipherBlock.data()), CipherBlock.size());
        Signer.update(CipherBlock.data(), std::cin.gcount());
        SymCipher->cipher(CipherBlock.data(), CipherBlock.data(), std::cin.gcount());
        fileOut.write(reinterpret_cast<char *> (CipherBlock.data()), std::cin.gcount());
        if (!fileOut.good())
            throw std::range_error("failed to write cipher block");
    }

    Signature = Signer.signature(PRNG);
    // signature
    fileOut.seekp(sizeSigPos + sizeof(u32SigSize));
    fileOut.write(reinterpret_cast<char *> (Signature.data()), Signature.size());
    if (!fileOut.good())
        throw std::range_error("failed to write signature");
    fileOut.seekp(0, std::ios_base::end);
}


static void decrypt (const std::string &wrapBaseName,
    const std::string &signBaseName, std::istream &fileIn, bool verify = false)
{
    Botan::AutoSeeded_RNG PRNG;

    std::unique_ptr<Botan::Public_Key> SignKey(
        Botan::X509::load_key(signBaseName + "_pub_ed25519.pem"));
    std::unique_ptr<Botan::Private_Key> WrapKey(
        Botan::PKCS8::load_key(wrapBaseName + "_priv_rsa.pem", PRNG));

    uint32_t u32WrappedSize = 0;
    uint32_t u32SigSize = 0;
    Botan::PK_Decryptor_EME WrapDecryptor(*WrapKey.get(), PRNG, "EME1(SHA-256)");
    std::vector<uint8_t> WrappedKey;
    std::vector<uint8_t> WrappedIV;
    std::vector<uint8_t> Signature;
    // wrapped key
    fileIn.read(reinterpret_cast<char *> (&u32WrappedSize), sizeof(u32WrappedSize));
    if (!fileIn.good())
        throw std::range_error("failed to read wrapped key size");
    WrappedKey.resize(u32WrappedSize);
    fileIn.read(reinterpret_cast<char *> (WrappedKey.data()), WrappedKey.size());
    if (!fileIn.good())
        throw std::range_error("failed to read wrapped key");
    // wrapped iv
    fileIn.read(reinterpret_cast<char *> (&u32WrappedSize), sizeof(u32WrappedSize));
    if (!fileIn.good())
        throw std::range_error("failed to read wrapped iv size");
    WrappedIV.resize(u32WrappedSize);
    fileIn.read(reinterpret_cast<char *> (WrappedIV.data()), WrappedIV.size());
    if (!fileIn.good())
        throw std::range_error("failed to read wrapped iv");
    // signature
    fileIn.read(reinterpret_cast<char *> (&u32SigSize), sizeof(u32SigSize));
    if (!fileIn.good())
        throw std::range_error("failed to read signature size");
    Signature.resize(u32SigSize);
    fileIn.read(reinterpret_cast<char *> (Signature.data()), Signature.size());
    if (!fileIn.good())
        throw std::range_error("failed to read signature");

    Botan::secure_vector<uint8_t> SymKey(WrapDecryptor.decrypt(WrappedKey));
    Botan::secure_vector<uint8_t> SymIV(WrapDecryptor.decrypt(WrappedIV));
    fprintf(stderr, "keysize=%lu, ivsize=%lu, sigsize=%lu\n",
        SymKey.size(), SymIV.size(), Signature.size());
    std::unique_ptr<Botan::StreamCipher> SymCipher(
        Botan::CTR_BE::create_or_throw("CTR(AES-256)"));
    SymCipher->set_key(SymKey);
    SymCipher->set_iv(SymIV.data(), SymIV.size());

    const size_t sizeBlock = 1048576 * 4;  // 4 MiB
    Botan::secure_vector<uint8_t> CipherBlock(sizeBlock);
    Botan::PK_Verifier Verifier(*SignKey.get(), "SHA-512");

    while (fileIn.good())
    {
        fileIn.read(reinterpret_cast<char *> (CipherBlock.data()), CipherBlock.size());
        SymCipher->cipher(CipherBlock.data(), CipherBlock.data(), fileIn.gcount());
        Verifier.update(CipherBlock.data(), fileIn.gcount());
        if (!verify)
        {
            std::cout.write(reinterpret_cast<char *> (CipherBlock.data()),
                fileIn.gcount());
            if (!std::cout.good())
                throw std::range_error("failed to write cipher block");
        }
    }

    if (Verifier.check_signature(Signature))
        std::cerr << "signature OK" << std::endl;
    else
        throw std::domain_error("signature check failed");
}


static void makesig (const std::string &signBaseName,
    const std::string &fileName)
{
    std::ifstream fileIn(fileName, std::ios_base::in | std::ios_base::binary);

    Botan::AutoSeeded_RNG PRNG;
    std::unique_ptr<Botan::Private_Key> SignKey(
        Botan::PKCS8::load_key(signBaseName + "_priv_ed25519.pem", PRNG));
    Botan::PK_Signer Signer(*SignKey.get(), PRNG, "SHA-512");

    uint32_t u32SigSize;
    u32SigSize = Signer.signature_length();
    std::vector<uint8_t> Signature(u32SigSize);
    fprintf(stderr, "sigsize=%u\n", u32SigSize);

    const size_t sizeBlock = 1048576 * 4;  // 4 MiB
    std::vector<uint8_t> SignBlock(sizeBlock);

    while (fileIn.good())
    {
        fileIn.read(reinterpret_cast<char *> (SignBlock.data()), SignBlock.size());
        Signer.update(SignBlock.data(), fileIn.gcount());
    }

    Signature = Signer.signature(PRNG);
    // signature
    std::cout.write(reinterpret_cast<char *> (&u32SigSize), sizeof(u32SigSize));
    if (!std::cout.good())
        throw std::range_error("failed to write signature size");
    std::cout.write(reinterpret_cast<char *> (Signature.data()), Signature.size());
    if (!std::cout.good())
        throw std::range_error("failed to write signature");
}


static void checksig (const std::string &signBaseName,
    const std::string &fileName)
{
    std::ifstream fileIn(fileName, std::ios_base::in | std::ios_base::binary);

    Botan::AutoSeeded_RNG PRNG;
    std::unique_ptr<Botan::Public_Key> SignKey(
        Botan::X509::load_key(signBaseName + "_pub_ed25519.pem"));
    Botan::PK_Verifier Verifier(*SignKey.get(), "SHA-512");

    uint32_t u32SigSize;
    std::cin.read(reinterpret_cast<char *> (&u32SigSize), sizeof(u32SigSize));
    if (!std::cin.good())
        throw std::range_error("failed to read signature size");
    std::vector<uint8_t> Signature(u32SigSize);
    fprintf(stderr, "sigsize=%u\n", u32SigSize);
    std::cin.read(reinterpret_cast<char *> (Signature.data()), Signature.size());
    if (!std::cin.good())
        throw std::range_error("failed to read signature");

    const size_t sizeBlock = 1048576 * 4;  // 4 MiB
    std::vector<uint8_t> SignBlock(sizeBlock);

    while (fileIn.good())
    {
        fileIn.read(reinterpret_cast<char *> (SignBlock.data()), SignBlock.size());
        Verifier.update(SignBlock.data(), fileIn.gcount());
    }

    if (Verifier.check_signature(Signature))
        std::cerr << "signature OK" << std::endl;
    else
        throw std::domain_error("signature check failed");
}


static void print_help (const char *execname)
{
    std::cerr << execname << " command args..." << std::endl;
    std::cerr << "\tkeygen <basename>" << std::endl;
    std::cerr << "\tencrypt <own basename> <recipient basename> [output filename]" << std::endl;
    std::cerr << "\tdecrypt <own basename> <sender basename> [input filename]" << std::endl;
    std::cerr << "\tverify <own basename> <sender basename> [input filename]" << std::endl;
    std::cerr << "\tmakesig <own basename> <file to sign>" << std::endl;
    std::cerr << "\tchecksig <sender basename> <signed file>" << std::endl;
}


int main (int argc, char *argv[])
{
    try
    {
        if (argc < 2)
        {
            print_help(argv[0]);
            return 1;
        }

        std::string Cmd(argv[1]);

        if (Cmd == "keygen" && argc == 3)
            keygen(std::string(argv[2]));
        else if (Cmd == "encrypt" && argc == 4)
            encrypt(std::string(argv[2]), std::string(argv[3]), std::cout);
        else if (Cmd == "encrypt" && argc == 5)
        {
            std::ofstream fileOut(argv[4],
                std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
            encrypt(std::string(argv[2]), std::string(argv[3]), fileOut);
        }
        else if (Cmd == "decrypt" && argc == 4)
            decrypt(std::string(argv[2]), std::string(argv[3]), std::cin);
        else if (Cmd == "decrypt" && argc == 5)
        {
            std::ifstream fileIn(argv[4],
                std::ios_base::in | std::ios_base::binary);
            decrypt(std::string(argv[2]), std::string(argv[3]), fileIn);
        }
        else if (Cmd == "verify" && argc == 4)
            decrypt(std::string(argv[2]), std::string(argv[3]), std::cin, true);
        else if (Cmd == "verify" && argc == 5)
        {
            std::ifstream fileIn(argv[4],
                std::ios_base::in | std::ios_base::binary);
            decrypt(std::string(argv[2]), std::string(argv[3]), fileIn, true);
        }
        else if (Cmd == "makesig" && argc == 4)
            makesig(std::string(argv[2]), std::string(argv[3]));
        else if (Cmd == "checksig" && argc == 4)
            checksig(std::string(argv[2]), std::string(argv[3]));
        else
            print_help(argv[0]);
    }
    catch (std::exception &x)
    {
        std::cerr << x.what() << std::endl;
        return 2;
    }
    catch (...)
    {
        std::cerr << "Unknown exception" << std::endl;
        return 3;
    }
    return 0;
}

