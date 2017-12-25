/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description: Hash key (Hash table) generation from a given string input        %
% (Function descriptions are presented individually (see below)                  %
%                                                                                %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Anvesh Ragi                 201x-xx-xx      Functions created                %
%--------------------------------------------------------------------------------*/

#include "ODSE_Trapdoor.h"
#include "Miscellaneous.h"
#include "Keyword_Extraction.h"
#include "ODSE_Crypto.h"
ODSE_Trapdoor::ODSE_Trapdoor()
{
}

ODSE_Trapdoor::~ODSE_Trapdoor()
{
    
}


/**
 * Function Name: generateTrapdoor_single_input
 *
 * Description:
 * Generate hash value of a string
 *
 * @param pOutData: (output) hash value
 * @param out_len: (output) length of hash value 
 * @param pInData: (input) input string
 * @param in_len: (input) length of input string
 * @param pKey: (input) symmetric key
 * @return	0 if successful
 */
int ODSE_Trapdoor::generateTrapdoor_single_input(unsigned char *pOutData,
		int out_len,
		unsigned char *pInData,
		int in_len,
		MasterKey *pKey) 
{	
	if(out_len>0 && in_len>0)
		omac_aes128(pOutData, out_len, pInData, in_len, pKey->key1);
	else
		cout << "Either length of input or output to data_trapdoor is <= 0" << endl;
	return 0;
}



