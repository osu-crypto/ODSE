/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description:                           									     %
% Cryptographic operations being used in ODSE with XOR-based PIR                 %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2016-09-13      Functions created                %
%--------------------------------------------------------------------------------*/


#include <tomcrypt.h>
#include "config.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef __SIZE_TYPE__ size_t;

int omac_aes128(unsigned char *omac_out, int omac_length, const unsigned char *data, int datalen, unsigned char *key);


#ifdef __cplusplus
}
#endif
