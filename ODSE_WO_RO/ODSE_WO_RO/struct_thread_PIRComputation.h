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
    zz_p** input;
    int start;
    int end;
    
    zz_p* select_vector;
    
    THREAD_PIR_COMPUTATION()
    {
        
    }
    ~THREAD_PIR_COMPUTATION()
    {
        
    }
    THREAD_PIR_COMPUTATION(zz_p** input, MatrixType* output, int start, int end, zz_p* select_vector)
    {
        this->output = output;
        this->input = input;
        this->start = start;
        this->end = end;
        this->select_vector = select_vector;
    }
};

#endif // STRUCT_THREAD_PRECOMPUTE_AESKEY_H
