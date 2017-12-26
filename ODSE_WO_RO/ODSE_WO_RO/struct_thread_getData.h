/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description:  thread structure to get data from server                         %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2016-09-13      Functions created                %
%--------------------------------------------------------------------------------*/


#ifndef STRUCT_THREAD_GETDATA_H
#define STRUCT_THREAD_GETDATA_H
#include "struct_MatrixType.h"
#include "config.h"
typedef struct THREAD_GETDATA
{
    MatrixType* data;
    std::set<TYPE_INDEX> column_indexes;
    unsigned char* idx_vector; //for search with Chor
    
    int server_id;
    THREAD_GETDATA()
    {
        
    }
    ~THREAD_GETDATA()
    {
        
    }
    THREAD_GETDATA(std::set<TYPE_INDEX> column_indexes, MatrixType* data)
    {
        this->column_indexes = column_indexes;
        this->data = data;
    }
};

#endif // STRUCT_THREAD_GETDATA_H
