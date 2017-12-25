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
#if defined (INTEL_AES_NI)
#include <iaes_asm_interface.h>
#include <iaesni.h>
#endif
#ifdef __cplusplus
extern "C" {
#endif
typedef __SIZE_TYPE__ size_t;


int aes128_ctr_encdec( unsigned char *pt, unsigned char *ct,  unsigned char *key,  unsigned char *ctr,  size_t numBlocks);

int omac_aes128(unsigned char *omac_out, int omac_length, const unsigned char *data, int datalen, unsigned char *key);

#if defined(INTEL_AES_NI)
int omac_aesni_init(omac_state *omac, int cipher, unsigned char *key);
int omac_aesni_process(omac_state *omac, unsigned char *key, const unsigned char *in, unsigned long inlen);
int omac_aesni_done(omac_state *omac, unsigned char *key, unsigned char *out, int outlen);
#endif

#ifdef __cplusplus
}
#endif
