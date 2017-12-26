# Oblivious Dynamic Searchable Encryption (ODSE) Framework

This framework contains the basic implementation of three ODSE schemes described in the full paper available on ePrint (https://eprint.iacr.org/2017/1158). Each ODSE scheme is implemented individually and separately. This project is built on CodeLite IDE (link: http://codelite.org). It is recommended to install CodeLite to load the full ODSE workspaces. 


# Required Libraries

1. ZeroMQ (download link: http://zeromq.org/intro:get-the-software)
2. Libtomcrypt (download link: https://github.com/libtom/libtomcrypt)
3. Google sparsehash (download link: https://github.com/sparsehash/sparsehash)
4. Intel AES-NI (*optional*) (for ODSE_RO_WO & ODSE_XOR_WO schemes) by (download link: https://software.intel.com/en-us/articles/download-the-intel-aesni-sample-library)
5. NTL library v9.10.0  (download link: http://www.shoup.net/ntl/download.html) 

# Installation/Configuration/Build/Complile Instructions

Detailed step-by-step instructions regarding building and installation of ODSE schemes is described in their own folder. Please refer to README.md located in each project folder for more details.

# Further Information
For any inquiries, bugs, and assistance on building and running the code, please feel free to contact Thang Hoang (hoangmin@oregonstate.edu).
