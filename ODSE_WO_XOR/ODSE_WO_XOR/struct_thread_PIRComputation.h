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

#ifndef STRUCT_THREAD_PIR_COMPUTATION_H
#define STRUCT_THREAD_PIR_COMPUTATION_H
#include "MasterKey.h"
#include "config.h"
typedef struct THREAD_PIR_COMPUTATION
{
    MatrixType* output;
    MatrixType** input;
    int start;
    int end;
    TYPE_INDEX* one_idx_arr;
    
    
    THREAD_PIR_COMPUTATION()
    {
        
    }
    ~THREAD_PIR_COMPUTATION()
    {
        
    }
    THREAD_PIR_COMPUTATION(MatrixType** input, MatrixType* output, int start, int end, TYPE_INDEX* one_idx_arr)
    {
        this->output = output;
        this->input = input;
        this->start = start;
        this->end = end;
        this->one_idx_arr = one_idx_arr;
    }
};

#endif // STRUCT_THREAD_PRECOMPUTE_AESKEY_H
