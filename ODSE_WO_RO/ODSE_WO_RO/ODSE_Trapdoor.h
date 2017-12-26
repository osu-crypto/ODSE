/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description: Hash key (Hash table) generation from a given string input        %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2017-12-21      Functions created                %
%--------------------------------------------------------------------------------*/

#ifndef ODSE_TRAODOOR_H
#define ODSE_TRAODOOR_H

#include "config.h"
#include "MasterKey.h"

class ODSE_Trapdoor
{
public:
    ODSE_Trapdoor();
    ~ODSE_Trapdoor();

     int generateTrapdoors(TYPE_GOOGLE_DENSE_HASH_MAP &rT_W,
		TYPE_GOOGLE_DENSE_HASH_MAP &rT_F,
		vector<string> &rFileNames,
		TYPE_KEYWORD_DICTIONARY &rKeywordsDictionary,
        TYPE_INDEX &max_row_idx,
        TYPE_INDEX &max_col_idx,
		string path,
		MasterKey *pKey);
    int generateTrapdoor_single_input(unsigned char *pOutData, int out_len, unsigned char *pInData, int in_len, MasterKey *pKey);

};

#endif // TRAPDOOR_FUNCTION_H
