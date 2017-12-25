/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description:  Symmetric key generation in ODSE with XOR-based PIR              %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2016-09-13      Functions created                %
%--------------------------------------------------------------------------------*/


#ifndef ODSE_KEYGEN_H
#define ODSE_KEYGEN_H

#include "MasterKey.h"
#include "struct_MatrixType.h"
class ODSE_KeyGen
{
public:
    ODSE_KeyGen();
    ~ODSE_KeyGen();
    
    int genMaster_key(MasterKey *pKey);
};

#endif // ODSE_KEYGEN_H
