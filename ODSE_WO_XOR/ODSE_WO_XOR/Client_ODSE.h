/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description: Client-side functionalities in ODSE with XOR-based PIR            %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2016-09-13      Functions created                %
%--------------------------------------------------------------------------------*/


#ifndef CLIENT_ODSE_H
#define CLIENT_ODSE_H

#include <MasterKey.h>
#include <config.h>
#include <struct_MatrixType.h>
#include <pthread.h>
#include "struct_thread_getData.h"
#include "struct_StashData.h"

class Client_ODSE
{
private:
    MasterKey* masterKey;
    
    // block counter
    TYPE_COUNTER* block_counter_arr;

    //keys
    unsigned char* row_keys;
    unsigned char* decrypt_col_key;
    unsigned char* reencrypt_col_key;
    
    //columns
    MatrixType* I_prime;
    
    TYPE_GOOGLE_DENSE_HASH_MAP T_W;
	TYPE_GOOGLE_DENSE_HASH_MAP T_F;
    
    // Stash
    bool ready = false;
        
    
    MatrixType **search_data;
    unsigned char* aes_keys;
    MatrixType *search_res;
        
    pthread_t thread_precomputeAesKey_decrypt;
    pthread_t thread_precomputeAesKey_reencrypt;
    pthread_t thread_getData[NUM_SERVERS];
    THREAD_GETDATA get_data_param [NUM_SERVERS];
    
    
    int downloadColumnBlock(int server_id, std::set<TYPE_INDEX> indexes,
                            MatrixType* I_prime);
    int uploadColumnBlock(int server_id, std::set<TYPE_INDEX> indexes, MatrixType *I_prime);
    int genMaster_key();
    int sendSearch_query(int server_id, unsigned char* row_vector, MatrixType* I_prime);

public:
    static std::set<TYPE_INDEX> lstDummy_column_idx;
    static std::set<TYPE_INDEX> lstFree_row_idx;
STASH S;
    

    Client_ODSE();
    ~Client_ODSE();
    int initMemory();
    
    int saveState();
    int loadState();
    
    int createEncryptedIndex();
    
    int sendEncryptedIndex();
    int sendFile(int server_id,string filename, string path, int SENDING_TYPE);
    int sendCommandOnly(int serverid, int cmd);
    
    int searchKeyword(string keyword, TYPE_COUNTER &number);
    
    int updateFile(string filename, string path);


    static void* thread_precomputeAesKey_func(void* param);
    static void* thread_getSearchData_func(void* param);
    static void* thread_downloadData_func(void* param);
    static void* thread_uploadData_func(void* param);
    
};

#endif // CLIENT_ODSE_H
