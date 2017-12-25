/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description:                           									     %
% ODSE cryptographic operations being used in ODSE with XOR-based PIR            %
% (Function descriptions are presented individually (see below)                  %
%                                                                                %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2016-09-13      Functions modifed                %
%   Anvesh Ragi                 201x-xx-xx      Functions created                %
%--------------------------------------------------------------------------------*/

#include "ODSE_Crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Function Name: omac_aes128
 *
 * Description:
 * Calculate AES-OMAC
 * 
 * @param omac_out: (output) output OMAC
 * @param omac_length: (input) length of OMAC
 * @param data: (input) data to be calculated
 * @param datalen: (input) length of input data (in bytes)
 * @param key: (input) secret key
 * @return	0 if successful
 */
//block_size and key_size are of 16 bytes & so outlen should be <=16
int omac_aes128(unsigned char *omac_out, int omac_length, const unsigned char *data, int datalen, unsigned char *key)
{
	int idx, err;
	omac_state omac;

	/* register Rijndael */
	if (register_cipher(&rijndael_desc) == -1) {
		printf("Error registering Rijndael\n");
		return -1;
	}
	/* get index of Rijndael in cipher descriptor table */
	idx = find_cipher("rijndael");
	/* we would make up our symmetric key in "key[]" here */
	/* start the OMAC */
    if ((err = omac_init(&omac, idx, key,BLOCK_CIPHER_SIZE)) != CRYPT_OK) {
		printf("Error setting up omac: %s\n", error_to_string(err));
		return -1;
	}
	/* process a few octets */
	if((err = omac_process(&omac, data, datalen)) != CRYPT_OK) {
		printf("Error processing omac: %s\n", error_to_string(err));
		return -1;
	}
    unsigned long ul_omac_len = omac_length;
	/* get result (presumably to use it somehow...) */
	if ((err = omac_done(&omac, omac_out, &ul_omac_len)) != CRYPT_OK) {
		printf("Error finishing omac: %s\n", error_to_string(err));
		return -1;
	}
    unregister_cipher(&rijndael_desc);
	return 0;
}


#ifdef __cplusplus
}
#endif