/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description:                                                                   % 
% Core functions of ODSE with XOR-based PIR                                      %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2016-09-13      Functions created                %
%--------------------------------------------------------------------------------*/


#ifndef ODSE_H
#define ODSE_H

#include "struct_MatrixType.h"
#include "struct_SearchToken.h"

#include "struct_UpdateToken.h"


class ODSE{
private:
    
    int scanDatabase(
		vector<string> &rFileNames,
		TYPE_KEYWORD_DICTIONARY &rKeywordsDictionary,
        TYPE_GOOGLE_DENSE_HASH_MAP &rT_W,
		TYPE_GOOGLE_DENSE_HASH_MAP &rT_F,
        string path,
        MasterKey* pKey);
        
    int createKeyword_file_pair(
        vector<vector<TYPE_INDEX>> &kw_file_pair,
		TYPE_GOOGLE_DENSE_HASH_MAP &rT_W,
		TYPE_GOOGLE_DENSE_HASH_MAP &rT_F,
        std::set<TYPE_INDEX> &lstFree_keyword_idx,
        std::set<TYPE_INDEX> &lstFree_file_idx,
		string path,
		MasterKey *pKey);
        
    int createEncrypted_matrix_from_kw_file_pair(vector<vector<TYPE_INDEX>> &kw_file_pair);

    int pickRandom_element(TYPE_INDEX &randomIdx,std::set<TYPE_INDEX> &setIdx);

public:
    ODSE();
    ~ODSE();
    int loadEncrypted_matrix_from_files(zz_p** I, int serverID);
    int saveEncrypted_matrix_to_files(zz_p** I, int serverID);
    
    int setupEncryptedIndex(
                            TYPE_GOOGLE_DENSE_HASH_MAP &rT_W, 
                            TYPE_GOOGLE_DENSE_HASH_MAP &rT_F, 
                            std::set<TYPE_INDEX> &lstDummy_column_idx,
                            std::set<TYPE_INDEX> &lstFree_row_idx,  
                            vector<string> &rFileNames, 
                            string path, 
                            MasterKey *pKey);
                                
    int searchToken(SEARCH_TOKEN &pSearchToken, 
                    string keyword,
                    TYPE_GOOGLE_DENSE_HASH_MAP &rT_W, 
                    MasterKey *pKey);
    int search( zz_p* index_vector, int start, int end, zz_p** I, MatrixType* I_prime);

    int updateToken(   
                        string update_filename,
                        string path,
                        std::set<TYPE_INDEX> indexes,
                        zz_p** I_prime,
                        STASH &S,
                        TYPE_GOOGLE_DENSE_HASH_MAP &rT_F,
                        TYPE_GOOGLE_DENSE_HASH_MAP &rT_W,
                        std::set<TYPE_INDEX> &lstDummy_column_idx,
                        std::set<TYPE_INDEX> &lstFree_row_idx,
                        TYPE_KEYWORD_DICTIONARY &extracted_keywords,
                        MasterKey* pKey);
    
    
    int update(zz_p* shares,               
            TYPE_INDEX block_idx,                             
            zz_p** I);
   
    
    int updateBlock(    MatrixType* updating_block,
                        unsigned char* input_block,
                        TYPE_INDEX update_idx);
    
    
    int getBlock( TYPE_INDEX index, zz_p** I, unsigned char* I_prime);
    
    void serializeFFElementVector(unsigned char* output, zz_p* idx_vector, TYPE_INDEX n);
    void deserializeFFElementVector(unsigned char* input, zz_p* idx_vector, TYPE_INDEX n);
    
    int createShare(zz_p input, zz_p* output);
    zz_p simpleRecover(zz_p* y, int privacy_level);                                        
};

#endif
