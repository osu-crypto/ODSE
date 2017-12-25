/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description: Generate master keys in ODSE with XOR-based PIR            	     %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 201x-xx-xx      Functions created                %
%--------------------------------------------------------------------------------*/

#ifndef MASTERKEY_H
#define MASTERKEY_H

#include <config.h>


struct MasterKey
{
    unsigned char key1[BLOCK_CIPHER_SIZE];
public:
    MasterKey()
    {
        
    };
    ~MasterKey()
    {
        
    };
    
};

#endif // MASTERKEY_H
