# ODSE: Oblivious Dynamic Searchable Encryption Framework

Basic implementation of 3 ODSE schemes. The full paper will be available soon. This project is built on CodeLite IDE (link: http://codelite.org). It is recommended to install CodeLite to load the full ODSE workspaces. 


# Required Libraries

1. ZeroMQ (download link: http://zeromq.org/intro:get-the-software)
2. Libtomcrypt (download link: https://github.com/libtom/libtomcrypt)
3. Google sparsehash (download link: https://github.com/sparsehash/sparsehash)
4. Intel AES-NI (*optional*) (for ODSE_RO_WO & ODSE_XOR_WO schemes) by (download link: https://software.intel.com/en-us/articles/download-the-intel-aesni-sample-library)
5. NTL library v9.10.0 (for ODSE_RO_WO & ODSE_WO_IT schemes) (download link: http://www.shoup.net/ntl/download.html) 
## Intel AES-NI installation guide (optional)
ODSE_RO_WO and ODSE_XOR_WO schemes leverage Intel AES-NI to accelerate cryptographic operations. The Intel-AES-NI is available in Intel® Core™ i5, Intel® Core™ i7, Intel® Xeon® 5600 series and newer processor (see https://ark.intel.com/Search/FeatureFilter?productType=processors&AESTech=true for a complete list). Note that this functionality can be *disabled* to test ODSE with other CPU models (see the Configuration Section below). Here the brief instruction to install Intel-AES-NI:

1. Extract the .zip file downloaded from https://software.intel.com/en-us/articles/download-the-intel-aesni-sample-library
2. Open the Terminal and go to `Intel_AESNI_Sample_Library_v1.2/intel_aes_lib`
3. Run `./mk_lnx_libXX.sh`, which will generate the header and library files in `intel_aes_lib/include/` and `intel_aes_lib/lib/xXX/` directories, respectively, where ``XX = 64`` (if your OS is 64 bits) or ``XX = 86`` (if your OS is 32 bits).
4. Add the `lib` prefix to the generated library file (`intel_aesXX.a -> libintel_aesXX.a`).
5. Copy header files and library files to your local folders (e.g., `/usr/local/include` and `/usr/local/lib`).


# Configuration
The configuration for each ODSE scheme is located in its own folder, under named ```config.h```. 

## Highlighted Parameters:
(tbd)

# Build & Compile
(tbd)
### If there is an error regarding to BOOL/bool type when compiling with Intel-aes-ni

- Access the AES-NI header file named ``iaesni.h``, go to line 51, and comment that line as follows:

```
#ifndef bool
//#define bool BOOL 			-> line 51
#endif
```

### If the hardware does not support Intel-aes-ni

1. Disable INTEL_AES_NI in ``IM-DSSE/config.h``

2. Remove the library linker ``-lintel-aes64``  in the make file ``IM-DSSE/MakeFile``


# Usage

(tbd)

## Local Testing:
(tbd)

## Real Network Testing:
(tbd)


# Further Information
For any inquiries, bugs, and assistance on building and running the code, please feel free to contact Thang Hoang (hoangmin@oregonstate.edu).
