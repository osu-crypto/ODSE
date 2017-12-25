/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description:  Symmetric key generation in ODSE with XOR-based PIR              %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2016-09-13      Functions created                %
%--------------------------------------------------------------------------------*/


#ifndef ODSE_KEYGEN_H
#define ODSE_KEYGEN_H

#include "MasterKey.h"
#include "struct_MatrixType.h"
class ODSE_KeyGen
{
public:
    ODSE_KeyGen();
    ~ODSE_KeyGen();
    
    int genMaster_key(MasterKey *pKey);
    
    
    int genRow_key(unsigned char *pOutData, int out_len, unsigned char *pInData, int in_len, MasterKey *pKey);
     
    int pregenerateRow_keys(
                            unsigned char output[MATRIX_ROW_SIZE*BLOCK_CIPHER_SIZE],
                            MasterKey *pKey);
    
    int precomputeAES_CTR_keys( unsigned char* key,
                                TYPE_INDEX idx, int op, int isIncremental,
                                TYPE_COUNTER* col_counter_arr, 
                                unsigned char* pregenRow_keys,
                                MasterKey *pKey);
    int enc_dec_preAESKey(MatrixType* output, 
                            MatrixType* input, 
                            unsigned char preKey[], 
                            TYPE_INDEX len);

};

#endif // ODSE_KEYGEN_H
