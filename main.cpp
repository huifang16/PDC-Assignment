#include "aes.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <cctype>

static bool validatePassword(const std::string& pwd, std::string& errorMsg) {
    if (pwd.length() < 8) {
        errorMsg = "Password must be at least 8 characters long.";
        return false;
    }

    bool hasLower = false;
    bool hasUpper = false;
    bool hasDigit = false;
    bool hasSpecial = false;

    for (unsigned char ch : pwd) {
        if (std::islower(ch)) hasLower = true;
        else if (std::isupper(ch)) hasUpper = true;
        else if (std::isdigit(ch)) hasDigit = true;
        else if (std::ispunct(ch)) hasSpecial = true;
    }

    if (!hasLower) {
        errorMsg = "Password must contain at least one lowercase letter (a-z).";
        return false;
    }
    if (!hasUpper) {
        errorMsg = "Password must contain at least one uppercase letter (A-Z).";
        return false;
    }
    if (!hasDigit) {
        errorMsg = "Password must contain at least one digit (0-9).";
        return false;
    }
    if (!hasSpecial) {
        errorMsg = "Password must contain at least one special character (e.d^&*).";
        return false;
    }

    return true;
}

static std::string joinPath(const std::string& folder, const std::string& file) {
    if (folder.empty()) return file;
    char last = folder.back();
    if (last == '/' || last == '\\') return folder + file;
    return folder + "/" + file;
}

static bool fileExists(const std::string& path) {
    std::ifstream f(path.c_str());
    return f.good();
}

static std::string makeDecryptedFilename(const std::string& inputPath) {
    std::string path = inputPath;

    size_t outPos = path.rfind("_out");
    if (outPos != std::string::npos) {
        return path.substr(0, outPos) + "_Final" + path.substr(outPos + 4);
    }

    size_t outShort = path.rfind("out.");
    if (outShort != std::string::npos) {
        return path.substr(0, outShort) + "Final." + path.substr(outShort + 4);
    }

    size_t dotPos = path.rfind('.');
    size_t slashPos = path.find_last_of("/\\");
    std::string base = (dotPos != std::string::npos && (slashPos == std::string::npos || dotPos > slashPos))
        ? path.substr(0, dotPos) : path;
    std::string ext = (dotPos != std::string::npos && (slashPos == std::string::npos || dotPos > slashPos))
        ? path.substr(dotPos) : "";

    for (char ch = 'a'; ch <= 'z'; ++ch) {
        std::string candidate = base + ch + "_Final" + ext;
        if (!fileExists(candidate)) {
            return candidate;
        }
    }
    return base + "_Final" + ext;
}

static std::string makeEncryptFilename(const std::string& inputPath) {
    size_t dotPos = inputPath.rfind('.');
    size_t slashPos = inputPath.find_last_of("/\\");

    std::string base = (dotPos != std::string::npos && (slashPos == std::string::npos || dotPos > slashPos))
        ? inputPath.substr(0, dotPos)
        : inputPath;
    std::string ext = (dotPos != std::string::npos && (slashPos == std::string::npos || dotPos > slashPos))
        ? inputPath.substr(dotPos)
        : "";

    for (char ch = 'a'; ch <= 'z'; ++ch) {
        std::string candidate = base + ch + "_out" + ext;
        if (!fileExists(candidate)) {
            return candidate;
        }
    }
    return base + "_out" + ext;
}

static std::string keyToHexString(const AESKey& key) {
    std::ostringstream oss;
    for (uint8_t b : key) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

static void runCrypt(const uint8_t* in, uint8_t* out, size_t len, const AESKey& key,
    uint64_t nonce, int engineChoice) {
    if (engineChoice == 2) {
        ctrCryptOpenMP(in, out, len, key, 8, false, nonce, 0);
    }
    else if (engineChoice == 3) {
        ctrCryptCUDA(in, out, len, key, 256, nonce, 0);
    }
    else {
        ctrCryptSerial(in, out, len, key, nonce, 0);
    }
}

static int selectEngine() {
    std::cout << "\nChoose Method:\n";
    std::cout << "  1. Serial\n";
    std::cout << "  2. OpenMP\n";
    std::cout << "  3. CUDA\n";
    std::cout << "Select (1-3): ";
    std::string choice;
    std::getline(std::cin, choice);
    if (choice == "2") return 2;
    if (choice == "3") return 3;
    return 1;
}

static bool tryReadSample(const std::string& folder, const std::string& rawName,
    std::vector<uint8_t>& data, std::string& resolvedPath) {
    std::vector<std::string> candidates;
    candidates.push_back(joinPath(folder, rawName));

    std::string withSpace = rawName;
    size_t pos = withSpace.find("sample");
    if (pos != std::string::npos && withSpace.size() > 6 && withSpace[6] != ' ') {
        withSpace.insert(6, " ");
        candidates.push_back(joinPath(folder, withSpace));
    }

    std::string noSpace = rawName;
    size_t spPos = noSpace.find("sample ");
    if (spPos != std::string::npos) {
        noSpace.erase(spPos + 6, 1);
        candidates.push_back(joinPath(folder, noSpace));
    }

    for (const auto& path : candidates) {
        if (readFile(path.c_str(), data) && !data.empty()) {
            resolvedPath = path;
            return true;
        }
    }
    return false;
}

template<typename Func>
static double measureTime(Func&& fn) {
    auto t0 = std::chrono::high_resolution_clock::now();
    fn();
    auto t1 = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double>(t1 - t0).count();
}

void handleEncrypt() {
    std::cout << "\n--- ENCRYPTION ---\n";
    std::cout << "Enter plaintext file path: ";
    std::string input;
    std::getline(std::cin, input);
    if (input.empty()) return;

    std::vector<uint8_t> plainData;
    std::string actualPath;
    if (!tryReadSample("", input, plainData, actualPath)) {
        std::cout << "Error: Cannot open '" << input << "'. Please check the path and folder.\n";
        return;
    }

    std::string userPass;
    std::string errMsg;
    while (true) {
        std::cout << "Enter password: ";
        std::getline(std::cin, userPass);
        if (userPass.empty()) {
            std::cout << "Password cannot be empty.\n";
            continue;
        }
        if (validatePassword(userPass, errMsg)) {
            break;
        }
        std::cout << "Password rejected: " << errMsg << " Please try again.\n";
    }

    uint64_t nonce = generateRandom64();
    uint64_t salt = generateRandom64();

    AESKey key = deriveKeyPBKDF2(userPass, salt, 10000);

    int engine = selectEngine();
    std::string outputFile = makeEncryptFilename(actualPath);

    std::vector<uint8_t> outputPayload(16 + plainData.size());
    for (int i = 0; i < 8; i++) {
        outputPayload[7 - i] = uint8_t(nonce >> (8 * i));
        outputPayload[15 - i] = uint8_t(salt >> (8 * i));
    }

    auto t0 = std::chrono::high_resolution_clock::now();
    runCrypt(plainData.data(), outputPayload.data() + 16, plainData.size(), key, nonce, engine);
    auto t1 = std::chrono::high_resolution_clock::now();
    double sec = std::chrono::duration<double>(t1 - t0).count();

    if (!writeFile(outputFile.c_str(), outputPayload)) {
        std::cout << "Error writing encrypted file.\n";
        return;
    }

    std::cout << "Target File    : " << actualPath << "\n";
    std::cout << "Method Used    : " << (engine == 2 ? "OpenMP" : (engine == 3 ? "CUDA" : "Serial")) << "\n";
    std::cout << "Time Elapsed   : " << std::fixed << std::setprecision(5) << sec << "s\n";
    std::cout << "Derived AES Key: " << keyToHexString(key) << "\n";
    std::cout << "Saved File     : " << outputFile << "\n";
}

void handleDecrypt() {
    std::cout << "\n--- DECRYPTION ---\n";
    std::cout << "Enter encrypted file path: ";
    std::string input;
    std::getline(std::cin, input);
    if (input.empty()) return;

    std::vector<uint8_t> fileData;
    std::string actualPath;
    if (!tryReadSample("", input, fileData, actualPath)) {
        std::cout << "Error opening ciphertext file: " << input << "\n";
        return;
    }

    if (fileData.size() < 16) {
        std::cout << "Error: File size too small.\n";
        return;
    }

    std::cout << "Enter password: ";
    std::string userPass;
    std::getline(std::cin, userPass);
    if (userPass.empty()) {
        std::cout << "Password cannot be empty.\n";
        return;
    }

    uint64_t nonce = 0, salt = 0;
    for (int i = 0; i < 8; i++) {
        nonce = (nonce << 8) | fileData[i];
        salt = (salt << 8) | fileData[8 + i];
    }

    AESKey key = deriveKeyPBKDF2(userPass, salt, 10000);

    size_t cipherSize = fileData.size() - 16;
    const uint8_t* cipherPayload = fileData.data() + 16;
    std::vector<uint8_t> recoveredData(cipherSize);

    int engine = selectEngine();
    std::string outputFile = makeDecryptedFilename(actualPath);

    auto t0 = std::chrono::high_resolution_clock::now();
    runCrypt(cipherPayload, recoveredData.data(), cipherSize, key, nonce, engine);
    auto t1 = std::chrono::high_resolution_clock::now();
    double sec = std::chrono::duration<double>(t1 - t0).count();

    if (!writeFile(outputFile.c_str(), recoveredData)) {
        std::cout << "Error writing decrypted file.\n";
        return;
    }

    std::cout << "Target File    : " << actualPath << "\n";
    std::cout << "Method Used    : " << (engine == 2 ? "OpenMP" : (engine == 3 ? "CUDA" : "Serial")) << "\n";
    std::cout << "Derived AES Key: " << keyToHexString(key) << "\n";
    std::cout << "Time Elapsed   : " << std::fixed << std::setprecision(5) << sec << " s\n";
    std::cout << "Saved File     : " << outputFile << "\n";
}

void handleVerify() {
    std::cout << "\n--- VERIFY ---\n";
    std::cout << "Enter file 1 path: ";
    std::string f1; std::getline(std::cin, f1);
    std::cout << "Enter file 2 path: ";
    std::string f2; std::getline(std::cin, f2);

    std::vector<uint8_t> d1, d2;
    std::string p1, p2;
    if (!tryReadSample("", f1, d1, p1) || !tryReadSample("", f2, d2, p2)) {
        std::cout << "Read failed. One or both files not found.\n";
        return;
    }
    std::cout << (d1 == d2 ? "SUCCESS: Both files are IDENTICAL!\n" : "FAILED: Files DO NOT match.\n");
}

void handleBenchmark() {
    std::cout << "\n--- AES 128 PERFORMANCE BENCHMARK ---\n";
    std::cout << "Enter folder path: ";
    std::string folder;
    std::getline(std::cin, folder);

    std::cout << "Enter number of files to benchmark: ";
    std::string countStr;
    std::getline(std::cin, countStr);
    int totalCount = 100;
    if (!countStr.empty()) {
        try { totalCount = std::stoi(countStr); }
        catch (...) { totalCount = 100; }
    }

    std::ofstream csvOut("results.csv");
    if (csvOut.is_open()) {
        csvOut << "Idx,Filename,Size_MB,Operation,Serial_s,OMP_2,OMP_4,OMP_8,CU_128,CU_256,CU_512\n";
    }

    warmUpCUDA();
    AESKey key = generateRandomKey();
    uint64_t benchNonce = generateRandom64();

    std::string headerLine(121, '=');
    std::string dashedLine(121, '-');

    std::cout << "\n" << headerLine << "\n";
    std::cout << std::string(45, ' ') << "AES-128 PERFORMANCE BENCHMARK\n";
    std::cout << headerLine << "\n";

    std::cout << " Idx | " << std::left << std::setw(15) << "Filename"
        << " | " << std::setw(8) << "Size(MB)"
        << " | " << std::setw(11) << "Operation"
        << " | " << std::setw(9) << "Serial(s)"
        << " | " << std::setw(7) << "OMP-2"
        << " | " << std::setw(7) << "OMP-4"
        << " | " << std::setw(7) << "OMP-8"
        << " | " << std::setw(7) << "CU-128"
        << " | " << std::setw(7) << "CU-256"
        << " | " << std::setw(7) << "CU-512"
        << " |\n";
    std::cout << headerLine << "\n";

    for (int i = 1; i <= totalCount; i++) {
        std::string rawName = "sample " + std::to_string(i) + ".txt";
        std::vector<uint8_t> plainData;
        std::string resolvedPath;

        if (!tryReadSample(folder, rawName, plainData, resolvedPath) || plainData.empty()) {
            std::cout << " " << std::left << std::setw(3) << i << " | "
                << std::setw(15) << rawName << " | SKIPPED - FILE NOT FOUND\n";
            std::cout << dashedLine << "\n" << std::flush;
            continue;
        }

        double realSizeMB = static_cast<double>(plainData.size()) / (1024.0 * 1024.0);
        std::vector<uint8_t> cipherData(plainData.size());
        std::vector<uint8_t> temp(plainData.size());

        ctrCryptSerial(plainData.data(), cipherData.data(), plainData.size(), key, benchNonce);

        for (int op = 0; op < 2; op++) {
            const uint8_t* inBuf = (op == 0) ? plainData.data() : cipherData.data();
            std::string opName = (op == 0) ? "Encryption" : "Decryption";

            double tSerial = measureTime([&]() {
                ctrCryptSerial(inBuf, temp.data(), plainData.size(), key, benchNonce);
                });
            double tOmp2 = measureTime([&]() {
                ctrCryptOpenMP(inBuf, temp.data(), plainData.size(), key, 2, false, benchNonce);
                });
            double tOmp4 = measureTime([&]() {
                ctrCryptOpenMP(inBuf, temp.data(), plainData.size(), key, 4, false, benchNonce);
                });
            double tOmp8 = measureTime([&]() {
                ctrCryptOpenMP(inBuf, temp.data(), plainData.size(), key, 8, false, benchNonce);
                });
            double tCu128 = measureTime([&]() {
                ctrCryptCUDA(inBuf, temp.data(), plainData.size(), key, 128, benchNonce);
                });
            double tCu256 = measureTime([&]() {
                ctrCryptCUDA(inBuf, temp.data(), plainData.size(), key, 256, benchNonce);
                });
            double tCu512 = measureTime([&]() {
                ctrCryptCUDA(inBuf, temp.data(), plainData.size(), key, 512, benchNonce);
                });

            if (op == 0) {
                std::cout << " " << std::left << std::setw(3) << i << " | "
                    << std::setw(15) << ("sample" + std::to_string(i) + ".txt") << " | "
                    << std::fixed << std::setprecision(4) << std::setw(8) << realSizeMB << " | ";
            }
            else {
                std::cout << "     | "
                    << std::setw(15) << " " << " | "
                    << std::setw(8) << " " << " | ";
            }

            std::cout << std::left << std::setw(11) << opName << " | "
                << std::fixed << std::setprecision(5) << std::setw(9) << tSerial << " | "
                << std::setprecision(4) << std::setw(7) << tOmp2 << " | "
                << std::setw(7) << tOmp4 << " | "
                << std::setw(7) << tOmp8 << " | "
                << std::setw(7) << tCu128 << " | "
                << std::setw(7) << tCu256 << " | "
                << std::setw(7) << tCu512 << " |\n";

            if (csvOut.is_open()) {
                csvOut << i << ","
                    << ("sample" + std::to_string(i) + ".txt") << ","
                    << realSizeMB << ","
                    << opName << ","
                    << tSerial << ","
                    << tOmp2 << ","
                    << tOmp4 << ","
                    << tOmp8 << ","
                    << tCu128 << ","
                    << tCu256 << ","
                    << tCu512 << "\n";
            }
        }
        std::cout << dashedLine << "\n" << std::flush;
    }

    if (csvOut.is_open()) {
        csvOut.close();
    }
}

int main() {
    while (true) {
        std::cout << "====================================================\n"
            << "          AES-128 CTR FILE PROCESSING TOOL          \n"
            << "====================================================\n"
            << "1. Encrypt File\n2. Decrypt File\n3. Verify Files\n4. Benchmark Performance\n5. Exit\n"
            << "----------------------------------------------------\n"
            << "Select an option (1-5): ";
        std::string choice;
        std::getline(std::cin, choice);
        if (choice == "1") handleEncrypt();
        else if (choice == "2") handleDecrypt();
        else if (choice == "3") handleVerify();
        else if (choice == "4") handleBenchmark();
        else if (choice == "5") break;
        else std::cout << "Invalid option. Please choose 1, 2, 3, 4, or 5.\n";
        std::cout << "\n";
    }
    return 0;
}