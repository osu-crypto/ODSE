/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description:  Stash data structure in ODSE with XOR-based PIR		    	     %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2016-09-13      Functions created                %
%--------------------------------------------------------------------------------*/

#ifndef STRUCT_STASH_DATA_H
#define STRUCT_STASH_DATA_H
#include "config.h"
typedef struct STASH_DATA
{
    string ID;
    unsigned char* column_data;
    
    STASH_DATA(string ID, unsigned char* column_data)
    {
        this->ID = ID;
        this->column_data = new unsigned char[MATRIX_ROW_SIZE/BYTE_SIZE];
        memcpy(this->column_data,column_data,MATRIX_ROW_SIZE/BYTE_SIZE);
    }
};
 
#endif
