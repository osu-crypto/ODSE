/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description:  SearchToken structure in ODSE with XOR-based PIR			     %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2016-09-13      Functions created                %
%--------------------------------------------------------------------------------*/


#ifndef SEARCH_TOKEN_H
#define SEARCH_TOKEN_H

typedef struct SearchToken{
	TYPE_INDEX row_index;
    unsigned char row_vector[NUM_SERVERS][MATRIX_ROW_SIZE/BYTE_SIZE];
}SEARCH_TOKEN;

#endif 