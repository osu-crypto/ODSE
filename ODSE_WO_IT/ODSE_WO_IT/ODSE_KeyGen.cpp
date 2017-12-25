/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description:  Symmetric key generation in ODSE with XOR-based PIR              %
% (Function descriptions are presented individually (see below)                  %
%                                                                                %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2016-09-13      Functions created                %
%--------------------------------------------------------------------------------*/

#include "ODSE_KeyGen.h"
#include "ODSE_Crypto.h"        // for traditional crypto primitives
#include "ODSE.h"
#include "Miscellaneous.h"

#include "NTL/ZZ.h"
using namespace NTL;
ODSE_KeyGen::ODSE_KeyGen()
{

}

ODSE_KeyGen::~ODSE_KeyGen()
{
    
}



/**
 * Function Name: genMaster_key
 *
 * Description:
 * Generate all symmetric keys used for ODSE encrypted data structure, file collection, and client hash tables
 *
 * @param pKey: (output) symmetric keys being generated
 * @param pPRK: (input) pseudo random key 
 * @param PRK_len: (input) length of pseudo random key
 * @param pXTS: (input) extractor salt
 * @param XTS_len: (input) length of extractor salt
 * @param pSKM: (input) Source key material
 * @param SKM_len: (input) length of source key material
 * @return	0 if successful
 */
 
int ODSE_KeyGen::genMaster_key(MasterKey *pKey)
{
    
    string key_loc;
    
	ZZ tmp;
    RandomBits(tmp,BLOCK_CIPHER_SIZE*BYTE_SIZE);
    BytesFromZZ(pKey->key1,tmp,BLOCK_CIPHER_SIZE);
    
    return 0;
}
