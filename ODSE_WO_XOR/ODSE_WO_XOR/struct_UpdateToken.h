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


#ifndef UPDATE_TOKEN_H
#define UPDATE_TOKEN_H

typedef struct UpdateToken{
	TYPE_INDEX block_index;
    
    unsigned char block_vector[NUM_SERVERS][NUM_BLOCKS/BYTE_SIZE];
}UPDATE_TOKEN;

#endif 