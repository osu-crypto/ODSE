/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description: thread structure for block key precomputation                     %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2016-09-13      Functions created                %
%--------------------------------------------------------------------------------*/

#ifndef STRUCT_THREAD_PRECOMPUTE_AESKEY_H
#define STRUCT_THREAD_PRECOMPUTE_AESKEY_H
#include "MasterKey.h"
#include "config.h"
typedef struct THREAD_PRECOMPUTE_AESKEY
{
    unsigned char* aes_keys;
    TYPE_INDEX idx;
    
    int dim;
    bool isIncremental;
    
    TYPE_COUNTER* block_counter_arr;
    unsigned char* row_keys;
    
    MasterKey* masterKey;
    
    
    //for update
    std::set<TYPE_INDEX> indexes;
    

    //for search
    THREAD_PRECOMPUTE_AESKEY(unsigned char* aes_keys, TYPE_INDEX idx, int dim, TYPE_COUNTER* block_counter_arr,unsigned char* row_keys, MasterKey* masterKey)
    {
        this->idx = idx;
        this->dim = dim;
        this->block_counter_arr = block_counter_arr;
        this->row_keys = row_keys;
        this->masterKey = masterKey;
        this->aes_keys = aes_keys;
    }    
    
    //for update
    THREAD_PRECOMPUTE_AESKEY(unsigned char* aes_keys, std::set<TYPE_INDEX> indexes, int dim, bool isIncremental, TYPE_COUNTER* block_counter_arr,unsigned char* row_keys, MasterKey* masterKey)
    {
        this->isIncremental = isIncremental;
        this->indexes = indexes;
        this->dim = dim;
        this->block_counter_arr = block_counter_arr;
        this->row_keys = row_keys;
        this->masterKey = masterKey;
        this->aes_keys = aes_keys;
    }
};

#endif // STRUCT_THREAD_PRECOMPUTE_AESKEY_H
