# 🛡️ Forket

> **Note:** This is an **educational project**. Forket is written for the purpose of learning modern C++, system programming, and understanding how antivirus software works under the hood. It is **not** intended to replace commercial security solutions.

**Forket** is a lightweight, signature-based antivirus scanner developed in C++. It is designed to run primarily on macOS (UNIX-based systems), featuring a command-line interface (CLI) for scanning files and directories.

## 🚀 Features

-   **Recursive Scanning:** Efficiently traverses directories using `std::filesystem`.
-   **Signature Detection:** Identifies malicious files using byte-pattern matching (currently supports EICAR test file).
-   **Modern C++:** Written using C++17 standards.
-   **Cross-Platform Architecture:** Built with CMake, making it adaptable for macOS, Linux, and Windows.

## 🛠️ Tech Stack

-   **Language:** C++17
-   **Build System:** CMake
-   **Compiler:** Clang (macOS) / GCC
-   **Dependencies:** Standard Template Library (STL)

## 📂 Project Structure

```text
Forket/
├── CMakeLists.txt       # Build configuration
├── src/                 # Source files (.cpp)
├── include/             # Header files (.hpp)
├── tests/               # Unit tests
└── README.md            # Documentation
```

## ⚙️ Build Instructions

To build Forket on macOS or Linux, ensure you have CMake and a C++ compiler installed.

1. Clone the repository:
```bash 
git clone https://github.com/your-username/forket.git
cd forket
```

2. Create a build directory:
```bash 
mkdir build
cd build
```

3. Configure and Compile:
```bash 
cmake ..
make
```

4. Run:
```bash 
./forket
```

# 📖 Usage
Forket is a CLI tool. You can run it by providing a target directory or file to scan.
code

```bash 
# Scan a specific directory
./forket scan /Users/username/Downloads

# Scan a specific file
./forket scan /Users/username/suspicious_file.exe
```

# 🗺️ Roadmap & Learning Goals
The development of Forket follows a step-by-step learning path:

Phase 1: Basic project setup (CMake) and file I/O. ✅

Phase 2: Simple signature-based scanning (finding substrings). ✅

Phase 3: Hash-based scanning (MD5/SHA256). ✅

Phase 4: Multithreading (using Thread Pools for faster scanning). ✅

Phase 5: Mach-O / PE file header analysis. ⏳

Phase 6: Real-time file monitoring (using macOS FSEvents). ⏳

# ⚠️ Disclaimer
This software is provided "as is", without warranty of any kind. The author is not responsible for any damage or data loss caused by the use of this software. Please do not use this tool to handle real malware samples unless you know what you are doing.