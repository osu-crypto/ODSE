# Information-theoretically (IT)-Secure ODSE using Shamir-Secret-Sharing (SSS)-based PIR and Write-Only ORAM

Basic implementation of the ODSE scheme using SSS-based PIR and Write-Only ORAM on SSS-based searchable index. The scheme is described under name $(ODSE^{WO}_{IT})$ in the full paper available on ePrint (https://eprint.iacr.org/2017/1158). This project is built on CodeLite IDE (link: http://codelite.org). It is recommended to install CodeLite to load the full ODSE workspace. 


# Required Libraries
1. ZeroMQ (download link: http://zeromq.org/intro:get-the-software)
2. Libtomcrypt (download link: https://github.com/libtom/libtomcrypt)
3. Google sparsehash (download link: https://github.com/sparsehash/sparsehash)
4. NTL library v9.10.0  (download link: http://www.shoup.net/ntl/download.html) 

# Configuration
The configuration for ODSE scheme is located at ``ODSE_WO_IT/config.h``. 

## Important Parameters:
```
static const unsigned long P = 512124571219774627;        -> prime field (should be ~ 60 bits to use NTL optimized instructions)
#define NP_BITS 59                                       -> the ceiling number of bits of P
#define FF_SIZE 64                                        -> define the size of finite field size (by bit and should be multiplication of 8 and larger than log2(P))



#define MAX_NUM_OF_FILES 12544                  -> define the maximum number of files in the DB (should be multiple of (FF_SIZE * 8)
#define MAX_NUM_KEYWORDS MAX_NUM_OF_FILES       -> define the maximum number of keywords (should be multiple of 8)
#define WRITE_ORAM_LAMBDA 30                    -> define the number of columns/blocks to be downloaded/uploaded in Write-Only ORAM


#define NUM_SERVERS 3                           -> define the number of servers in the system (should be at least 3)
#define PRIVACY_LEVEL 1                         -> definve the privacy parameter t in SSS (should be (NUM_SERVER - 1)/2)
const int SERVER_ID[NUM_SERVERS] ={1,2,3};      -> define ID of servers (should be from 1....P-1)

const std::string SERVER_ADDR[NUM_SERVERS] = {"tcp://localhost:", "tcp://localhost:"};  -> define IP address of servers
const std::string SERVER_PORT[NUM_SERVERS] = {"5555","5556"};                           -> define port of servers


const long long int vandermonde[NUM_SERVERS] = {3,-3+P,1};  ->define the first row of inverse of Vandermonde matrix (corresponding to defined SERVER_IDs)

```

### Notes

The folder ``ODSE_WO_IT/data`` as well as its subfolders are required to store generated encrypted index and client state. The database input is located in ``ODSE_WO_IT/data/DB``. All these locations can be changed in the `config.h` file. The implementation recognize DB as a set of document files so that you can copy your DB files to this location. The current DB contains a very small subset of enron DB (link: https://www.cs.cmu.edu/~./enron/).


# Build & Compile
Goto folder ``ODSE_WO_IT/`` and execute
``` 
make
```

, which produces the binary executable file named ```ODSE_WO_IT``` in ``ODSE_WO_IT/Debug/``.

# Usage

Run the binary executable file ```ODSE_WO_IT```, which will ask for either Client or Server mode. The scheme can be tested using either **single** machine or **multiple** machines with network:

## Local Testing:
1. Set ``SERVER_ADDR`` in ``IM-DSSE/config.h`` to be ``localhost``. 
2. Compile the code with ``make`` in the ``ODSE_WO_IT/`` folder. 
4. Go to ``ODSE_WO_IT/Debug`` and run the compiled ``ODSE_WO_IT`` file with two different Terminals, each playing the client/server role.

Note that when running the binary file and selecting the <b>option 1</b> to initalize the encrypted index, press 'n' to avoid transmitting whole encrypted index to the server.

## Real Network Testing:
1. Set ``SERVER_ADDR`` and  ``SERVER_PORT`` in ``ODSE_WO_IT/config.h`` with the corresponding servers' IP address  and port number.
2. Run ``make`` in ``ODSE_WO_IT/`` to compile and generate executable file ``ODSE_WO_IT`` in ``ODSE_WO_IT/Debug`` folder.
3. Copy the file ``ODSE_WO_IT`` in ``ODSE_WO_IT/Debug`` to the servers
4. Execute the file and follow the instruction on the screen.


# Further Information
For any inquiries, bugs, and assistance on building and running the code, please feel free to contact Thang Hoang (hoangmin@oregonstate.edu).
