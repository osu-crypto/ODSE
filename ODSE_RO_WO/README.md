# ODSE scheme using Shamir-Secret-Sharing (SSS)-based PIR and Write-Only ORAM

Basic implementation of the ODSE scheme using SSS-based PIR and Write-Only ORAM. The scheme is described under name $(ODSE^{RO}_{WO})$ in the full paper available on ePrint (https://eprint.iacr.org/2017/1158). This project is built on CodeLite IDE (link: http://codelite.org). It is recommended to install CodeLite to load the full ODSE workspace. 


# Required Libraries
1. ZeroMQ (download link: http://zeromq.org/intro:get-the-software)
2. Libtomcrypt (download link: https://github.com/libtom/libtomcrypt)
3. Google sparsehash (download link: https://github.com/sparsehash/sparsehash)
4. Intel AES-NI (*optional*) (download link: https://software.intel.com/en-us/articles/download-the-intel-aesni-sample-library)
5. NTL library v9.10.0  (download link: http://www.shoup.net/ntl/download.html) 
## Intel AES-NI installation guide (optional)

ODSE scheme leverages Intel AES-NI to accelerate cryptographic operations. The Intel-AES-NI is available in Intel® Core™ i5, Intel® Core™ i7, Intel® Xeon® 5600 series and newer processor (see https://ark.intel.com/Search/FeatureFilter?productType=processors&AESTech=true for a complete list). Note that this functionality can be *disabled* to test ODSE with other CPU models (see the Configuration Section below). Here the brief instruction to install Intel-AES-NI:

1. Extract the .zip file downloaded from https://software.intel.com/en-us/articles/download-the-intel-aesni-sample-library
2. Open the Terminal and go to `Intel_AESNI_Sample_Library_v1.2/intel_aes_lib`
3. Run `./mk_lnx_libXX.sh`, which will generate the header and library files in `intel_aes_lib/include/` and `intel_aes_lib/lib/xXX/` directories, respectively, where ``XX = 64`` (if your OS is 64 bits) or ``XX = 86`` (if your OS is 32 bits).
4. Add the `lib` prefix to the generated library file (`intel_aesXX.a -> libintel_aesXX.a`).
5. Copy header files and library files to your local folders (e.g., `/usr/local/include` and `/usr/local/lib`).


# Configuration
The configuration for ODSE scheme is located at ``ODSE_RO_WO/config.h``. 

## Configurable Parameters:

#define ENCRYPT_BLOCK_SIZE 64                   -> define the block size of encryption (should be multiple of 8)

#define MAX_NUM_OF_FILES 12544                  -> define the maximum number of files in the DB (should be multiple of (ENCRYPT_BLOCK_SIZE * 8)
#define MAX_NUM_KEYWORDS MAX_NUM_OF_FILES       -> define the maximum number of keywords (should be multiple of 8)

#define WRITE_ORAM_LAMBDA 30                    -> define the number of columns/blocks to be downloaded/uploaded in Write-Only ORAM

#define INTEL_AES_NI                            -> define to enable using Intel AES-NI instruction to accelerate crypto operations

#define NUM_SERVERS 2                           -> define the number of servers in the system


const std::string SERVER_ADDR[NUM_SERVERS] = {"tcp://localhost:", "tcp://localhost:"};  -> define IP address of servers

const std::string SERVER_PORT[NUM_SERVERS] = {"5555","5556"};                           -> define port of servers

# Build & Compile
Goto folder ``ODSE_RO_WO/`` and execute
``` 
make
```

, which produces the binary executable file named ```ODSE_RO_WO``` in ``ODSE_RO_WO/Debug/``.

### If there is an error regarding to BOOL/bool type when compiling with Intel-aes-ni

- Access the AES-NI header file named ``iaesni.h``, go to line 51, and comment that line as follows:

```
#ifndef bool
//#define bool BOOL 			-> line 51
#endif
```

### If the hardware does not support Intel-aes-ni

1. Disable INTEL_AES_NI in ``IM-DSSE/config.h``

2. Remove the library linker ``-lintel-aes64``  in the make file ``ODSE_RO_WO/MakeFile``


# Usage

Run the binary executable file ```ODSE_RO_WO```, which will ask for either Client or Server mode. The scheme can be tested using either **single** machine or **multiple** machines with network:

## Local Testing:
1. Set ``SERVER_ADDR`` in ``IM-DSSE/config.h`` to be ``localhost``. 
2. Compile the code with ``make`` in the ``ODSE_RO_WO/`` folder. 
4. Go to ``ODSE_RO_WO/Debug`` and run the compiled ``ODSE_RO_WO`` file with two different Terminals, each playing the client/server role.

Note that when running the binary file and selecting the <b>option 1</b> to initalize the encrypted index, press 'n' to avoid transmitting whole encrypted index to the server.

## Real Network Testing:
1. Set ``SERVER_ADDR`` and  ``SERVER_PORT`` in ``ODSE_RO_WO/config.h`` with the corresponding servers' IP address  and port number.
2. Run ``make`` in ``ODSE_RO_WO/`` to compile and generate executable file ``ODSE_RO_WO`` in ``ODSE_RO_WO/Debug`` folder.
3. Copy the file ``ODSE_RO_WO`` in ``ODSE_RO_WO/Debug`` to the servers
4. Execute the file and follow the instruction on the screen.


# Further Information
For any inquiries, bugs, and assistance on building and running the code, please feel free to contact Thang Hoang (hoangmin@oregonstate.edu).
