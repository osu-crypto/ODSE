/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description:                                                                   % 
% Core functions of ODSE with XOR-based PIR                                      %
% (Function descriptions are presented individually (see below)                  %
%                                                                                %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2016-09-13      Functions created                %
%--------------------------------------------------------------------------------*/

#include "MasterKey.h" 
#include "ODSE.h"
#include "Keyword_Extraction.h"    
#include "Miscellaneous.h" 
#include "ODSE_Trapdoor.h"
#include "ODSE_Crypto.h"
#include "ODSE_KeyGen.h"
#include "climits"
#include "math.h"

#include "NTL/ZZ.h"
#include "Server_ODSE.h"
ODSE::ODSE()
{
    
}

ODSE::~ODSE()
{
}

/**
 * Function Name: scanDatabase
 *
 * Description:
 * Scan the file collection to determine the total numbers of files and unique keywords being extracted, and to estimate the size of 2 hash tables at client
 *
 * @param rFileName: (output) list of files in the file collection
 * @param rKeywordDictionary: (output) list of unique keywords being extracted
 * @param rT_W: (output) keyword hash table
 * @param rT_F: (output) file hash table
 * @param path: (input) location of the file collection
 * @param pKey: (input) symmetric keys
 * @return	0 if successful
 */
int ODSE::scanDatabase(
		vector<string> &rFileNames,
		TYPE_KEYWORD_DICTIONARY &rKeywordsDictionary,
        TYPE_GOOGLE_DENSE_HASH_MAP &rT_W,
		TYPE_GOOGLE_DENSE_HASH_MAP &rT_F,
        string path,
        MasterKey* pKey)
{

	int keyword_len = 0;
	unsigned char keyword_trapdoor[TRAPDOOR_SIZE], file_trapdoor[TRAPDOOR_SIZE];
	string word;
	DIR *pDir;
	struct dirent *pEntry;
	struct stat file_stat;
	string file_name, file_name_with_path;
	TYPE_KEYWORD_DICTIONARY words_per_file;
	std::set<string>::iterator iter;
    ODSE_Trapdoor* odse_trapdoor = new ODSE_Trapdoor();
    int ret = 0;
	try
    {
		if((pDir=opendir(path.c_str())) != NULL)
        {
			while((pEntry = readdir(pDir))!=NULL)
            {
				file_name = pEntry->d_name;
				if(!file_name.compare(".") || !file_name.compare("..")) 
                {
					continue;
				}
				else
                {
					file_name_with_path = path + pEntry->d_name;                                      // "/" +

					// If the file is a directory (or is in some way invalid) we'll skip it
					if (stat(file_name_with_path.c_str(), &file_stat)) continue;

					if (S_ISDIR(file_stat.st_mode))
                    {
						file_name_with_path.append("/");
                        scanDatabase(rFileNames, rKeywordsDictionary, rT_W, rT_F, file_name_with_path,pKey);
						continue;
					}
                    if(file_name.size() > 0)
                    {
						if((ret = odse_trapdoor->generateTrapdoor_single_input(file_trapdoor, TRAPDOOR_SIZE,	
								(unsigned char *)file_name.c_str(), 
								file_name.size(), pKey))!=0)
                        {
                            goto exit;
                        }
                    }
					else
						printf("File name is empty\n");

					hashmap_key_class hmap_file_trapdoor(file_trapdoor,TRAPDOOR_SIZE);
                    
                    rT_F[hmap_file_trapdoor] = FILE_NOT_EXIST; // assign empty values to this
                    
					rFileNames.push_back(file_name.c_str());
            
                    KeywordExtraction* wordext = new KeywordExtraction(); 
					wordext->extractKeywords(words_per_file, file_name, path);

					for(iter=words_per_file.begin();iter != words_per_file.end();iter++) 
                    {
                        word = *iter;
						keyword_len = word.size();
                        if(keyword_len>0)
                        {
							if((ret = odse_trapdoor->generateTrapdoor_single_input(keyword_trapdoor, TRAPDOOR_SIZE, 
									(unsigned char *)word.c_str(), keyword_len, pKey))!=0)
                            {
                                goto exit;
                            }
                            rKeywordsDictionary.insert(word);
                        }
						else
                        {
                            continue;
                        }
						hashmap_key_class hmap_keyword_trapdoor(keyword_trapdoor,TRAPDOOR_SIZE);
    
                        rT_W[hmap_keyword_trapdoor] = KEYWORD_NOT_EXIST;
                        
                        // Clearing contents
						word.clear();
					}
					// Clearing contents
					words_per_file.clear();
					file_name_with_path.clear();
				}
				// Clearing contents
				file_name.clear();
			}

			closedir(pDir);
		}
		else
        {
			cout << "Could not locate the directory..." << endl;
		}
	}
    catch(exception &e)
    {
		cout << "Error occurred in generate_file_trapdoors function " << e.what() << endl;
	}
exit:
	return ret;
}


/**
 * Function Name: createKeyword_file_pair
 *
 * Description:
 * create keyword-file pair from the file collection
 *
 * @param kw_file_pair: (output) list of keyword-file pair being extracted
 * @param rT_W: (output) keyword hash table 
 * @param rT_F: (output) file hash table
 * @param lstFree_keyword_idx: (input) list of empty indices used for keyword (e.g., empty row index)
 * @param lstFree_file_idx: (input) list of empty indices used for file (e.g., empty column index)
 * @param path: (input) location of the file collection
 * @param pKey: (input) key generated by genMasterKey which is used for hash table
 * @return	0 if successful
 */
int ODSE::createKeyword_file_pair(
        vector<vector<TYPE_INDEX>> &kw_file_pair,
		TYPE_GOOGLE_DENSE_HASH_MAP &rT_W,
		TYPE_GOOGLE_DENSE_HASH_MAP &rT_F,
        std::set<TYPE_INDEX> &lstFree_keyword_idx,
        std::set<TYPE_INDEX> &lstFree_file_idx,
		string path,
		MasterKey *pKey)
{
	int keyword_len = 0;
    int ret;
	TYPE_INDEX row = 0,file_index = 0;
	unsigned char keyword_trapdoor[TRAPDOOR_SIZE];
	unsigned char file_trapdoor[TRAPDOOR_SIZE];
	string word;
	DIR *pDir;
	struct dirent *pEntry;
	struct stat file_stat;
	string file_name, file_name_with_path;
	TYPE_KEYWORD_DICTIONARY words_per_file;
	std::set<string>::iterator iter;

    KeywordExtraction* kw_ex = new KeywordExtraction();
    ODSE_Trapdoor* odse_trapdoor = new ODSE_Trapdoor();
    
    TYPE_INDEX selectedIdx;
    try
    {
		if((pDir=opendir(path.c_str())) != NULL)
        {
			while((pEntry = readdir(pDir))!=NULL)
            {
				file_name = pEntry->d_name;
                // look into pEntry 
				if(!file_name.compare(".") || !file_name.compare("..")) 
                {
					continue;
				}
				else
                {
					file_name_with_path = path + pEntry->d_name; 
					// If the file is a directory (or is in some way invalid) we'll skip it
					if (stat(file_name_with_path.c_str(), &file_stat)) 
                        continue;
					if (S_ISDIR(file_stat.st_mode))
                    {
						file_name_with_path.append("/");
						createKeyword_file_pair(kw_file_pair, rT_W, rT_F, lstFree_keyword_idx, lstFree_file_idx, file_name_with_path, pKey);
						continue;
					}
					if(file_name.size() > 0)
                    {
						if((ret = odse_trapdoor->generateTrapdoor_single_input(file_trapdoor, TRAPDOOR_SIZE,	
								(unsigned char *)file_name.c_str(), 
								file_name.size(), pKey))!=0)
                        {
                            goto exit;
                        }
                    }
					else
						printf("File name is empty\n");

					hashmap_key_class hmap_file_trapdoor(file_trapdoor,TRAPDOOR_SIZE);
                    
					// Get the file index from the hashmap
                    if(rT_F[hmap_file_trapdoor] == FILE_NOT_EXIST)
                    {
                        this->pickRandom_element(selectedIdx,lstFree_file_idx);
                        rT_F[hmap_file_trapdoor] = selectedIdx;
                    }	
                   
					if((ret = kw_ex->extractKeywords(words_per_file, file_name, path))!=0)
                    {
                        goto exit;
                    }
                    
                    for(iter=words_per_file.begin();iter != words_per_file.end();iter++) 
                    {
						word = *iter;
						keyword_len = word.size();
                        if(keyword_len>0)
                        {
							if((ret = odse_trapdoor->generateTrapdoor_single_input(keyword_trapdoor, TRAPDOOR_SIZE, 
									(unsigned char *)word.c_str(), keyword_len, pKey))!=0)
                            {
                                goto exit;
                            }
                        }
						else
                        {
                            continue;
                        }
						hashmap_key_class hmap_keyword_trapdoor(keyword_trapdoor,TRAPDOOR_SIZE);
    
                        if(rT_W[hmap_keyword_trapdoor] == KEYWORD_NOT_EXIST)
                        {
                            this->pickRandom_element(selectedIdx,lstFree_keyword_idx);
                            rT_W[hmap_keyword_trapdoor] = selectedIdx;
                            
                        }
                        row = rT_W[hmap_keyword_trapdoor];

                        file_index = rT_F[hmap_file_trapdoor];
                        
                        //build the keyword file pair
                        kw_file_pair[file_index].push_back(row);
                    
						word.clear();
					}
					words_per_file.clear();
					file_name_with_path.clear();
				}
				file_name.clear();
			}

			closedir(pDir);
		}
		else
        {
			printf("Could not locate the directory...\n");
		}
	}
    catch(exception &e)
    {
        ret = -1;
		cout << "Error occurred in initializeMatrix function " << e.what() << endl;
        goto exit;
	}
    ret = 0;
    
exit:
    memset(keyword_trapdoor,0,TRAPDOOR_SIZE);
	memset(file_trapdoor,0,TRAPDOOR_SIZE);
	word.clear();
	delete pEntry;
	file_name.clear(); 
    file_name_with_path.clear();
	words_per_file.clear();
	delete kw_ex;
    delete odse_trapdoor;
	
    return ret;
}

/**
 * Function Name: createEncrypted_matrix_from_kw_file_pair
 *
 * Description:
 * create the encrypted index from the keyword-file pairs extracted and write it to file named FILENAME_MATRIX (config.h)
 *
 * @param kw_file_pair: (input) list of keyword-file pair being extracted
 * @param block_counter_arr: (input) column (block) counters
 * @param pKey: (input) key generated by genMasterKey which is used to encrypt ODSE data structure
 * @return	0 if successful
 */
int ODSE::createEncrypted_matrix_from_kw_file_pair(vector<vector<TYPE_INDEX>> &kw_file_pair,
                                                    TYPE_COUNTER* block_counter_arr,
                                                    MasterKey *pKey)
{
    int n; 
    TYPE_INDEX curIdx;
    TYPE_INDEX size_row;
    TYPE_INDEX col, row, row_idx;
    TYPE_INDEX vector_idx = 0;
    TYPE_INDEX ii,jj;
    int bit_number;
    Miscellaneous misc;
    n = MATRIX_COL_SIZE/MATRIX_PIECE_COL_SIZE;
    int ret;
    
    unsigned char U[BLOCK_CIPHER_SIZE];
    unsigned char V[BLOCK_CIPHER_SIZE];
    unsigned char uchar_counter[BLOCK_CIPHER_SIZE];
    TYPE_INDEX block_idx;
    unsigned char row_key [BLOCK_CIPHER_SIZE];
    unsigned char row_key_input [BLOCK_CIPHER_SIZE];
    ODSE_KeyGen* odse_keygen = new ODSE_KeyGen();
    
    MatrixType** I = new MatrixType*[MATRIX_ROW_SIZE];
    for(TYPE_INDEX m = 0 ; m < MATRIX_ROW_SIZE; m++)
    {
        I[m] = new MatrixType[MATRIX_PIECE_COL_SIZE];
        memset(I[m],0,MATRIX_PIECE_COL_SIZE);
    }
    
    block_idx = 0;
    for(int i = 0 ; i < n ; i++)
    {
        cout<<endl<<i<<"...."<<endl;
        for(TYPE_INDEX m = 0 ; m < MATRIX_ROW_SIZE; m++)
        {
            memset(I[m],0,MATRIX_PIECE_COL_SIZE);
        }
        for(curIdx  = MATRIX_PIECE_COL_SIZE*i,col=0; curIdx < MATRIX_PIECE_COL_SIZE * (i+1); col++,curIdx++)
        {
            for(bit_number = 0 ; bit_number < BYTE_SIZE; bit_number++)
            {
                vector_idx = curIdx * BYTE_SIZE + bit_number;
                for(row = 0, size_row = kw_file_pair[vector_idx].size(); row < size_row; row++)
                {
                    row_idx = kw_file_pair[vector_idx][row];
                    BIT_SET(&I[row_idx][col].byte_data,bit_number);
                }
            }
        }
        // encrypt block by block, there are two options:
        if(ENCRYPT_BLOCK_SIZE < BYTE_SIZE) // block size < byte size
        {
            for(row = 0 ; row < MATRIX_ROW_SIZE ; row++)
            {
                memset(row_key_input,0,BLOCK_CIPHER_SIZE);
                memcpy(row_key_input,&row,sizeof(row));
                if((ret = odse_keygen->genRow_key(row_key, BLOCK_CIPHER_SIZE, row_key_input, BLOCK_CIPHER_SIZE, pKey))!=0)
                {
                    goto exit;
                }
                block_idx = (MATRIX_PIECE_COL_SIZE*BYTE_SIZE/ENCRYPT_BLOCK_SIZE)*i; 
                for(jj = 0; jj < MATRIX_PIECE_COL_SIZE*BYTE_SIZE; jj+=ENCRYPT_BLOCK_SIZE,block_idx++)
                {
                    col = jj / BYTE_SIZE;
                    for(ii=0, bit_number = jj % BYTE_SIZE ; ii< ENCRYPT_BLOCK_SIZE;ii++,bit_number++)
                    {
                        if(BIT_CHECK(&I[row][col].byte_data,bit_number))
                            BIT_SET(&U[0],ii);
                        else
                            BIT_CLEAR(&U[0],ii);
                    }
                    memset(uchar_counter,0,BLOCK_CIPHER_SIZE);
                    memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&block_counter_arr[block_idx],sizeof(TYPE_COUNTER));
                    memcpy(&uchar_counter,&block_idx,sizeof(TYPE_INDEX));
                    // Encrypting the  matrix I using AES CTR 128 function
                    aes128_ctr_encdec(U, V, row_key, uchar_counter, ONE_VALUE);
                    // Write the encryped row back to matrix I
                    for(ii=0,bit_number = jj % BYTE_SIZE ; ii< ENCRYPT_BLOCK_SIZE;ii++,bit_number++)
                    {
                    
                        if(BIT_CHECK(&V[0],ii))
                            BIT_SET(&I[row][col].byte_data,bit_number);
                        else
                            BIT_CLEAR(&I[row][col].byte_data,bit_number);
                    }
                }
            }
        }
        else // encrypt block size > byte_size
        {
            if(ENCRYPT_BLOCK_SIZE % BYTE_SIZE != 0)
            {
                printf("Invalid block size, it should be divisible by 8 and not larger than 128");
                ret = -1;
                goto exit;
            }
            
            for(row = 0 ; row < MATRIX_ROW_SIZE ; row++)
            {
                memset(row_key_input,0,BLOCK_CIPHER_SIZE);
                memcpy(row_key_input,&row,sizeof(row));
                if((ret = odse_keygen->genRow_key(row_key, BLOCK_CIPHER_SIZE, row_key_input, BLOCK_CIPHER_SIZE, pKey))!=0)
                {
                    goto exit;
                }
                block_idx = (MATRIX_PIECE_COL_SIZE*BYTE_SIZE/ENCRYPT_BLOCK_SIZE)*i;
                for(col = 0; col < MATRIX_PIECE_COL_SIZE; col+=(ENCRYPT_BLOCK_SIZE/BYTE_SIZE),block_idx++)
                {
                    for(jj = col,ii=0; ii<ENCRYPT_BLOCK_SIZE/BYTE_SIZE;jj++, ii++)
                    {
                        U[ii] = I[row][jj].byte_data;
                    }
                    memset(uchar_counter,0,BLOCK_CIPHER_SIZE);
                    memcpy(&uchar_counter[BLOCK_CIPHER_SIZE/2],&block_counter_arr[block_idx],sizeof(TYPE_COUNTER));
                    memcpy(&uchar_counter,&block_idx,sizeof(TYPE_INDEX));
                    // Encrypting the  matrix I using AES CTR 128 function
                    aes128_ctr_encdec(U, V, row_key, uchar_counter, ONE_VALUE);
                    for(jj = col,ii=0; ii<ENCRYPT_BLOCK_SIZE/BYTE_SIZE;jj++, ii++)
                    {
                        I[row][jj].byte_data = V[ii];
                    }
               } 
            }
        }
        //write the matrix to file by spliting it to smaller chunks
        for(TYPE_INDEX m = 0 ; m < MATRIX_ROW_SIZE ; m +=MATRIX_PIECE_ROW_SIZE)
        {
            string filename = misc.to_string(m) + "_" + misc.to_string(i*MATRIX_PIECE_COL_SIZE);
            misc.write_matrix_to_file(filename,gcsEncryptedIdxPath,&I[m],MATRIX_PIECE_ROW_SIZE,MATRIX_PIECE_COL_SIZE);
        }
        ret = 0;
    }
exit:
    for(TYPE_INDEX m = 0 ; m < MATRIX_ROW_SIZE; m++)
    {
        delete [] I[m];
    }
    delete[] I;
    return ret;
}


/**
 * Function Name: saveEncrypted_matrix_to_files
 *
 * Description:
 * Save the ODSE encrypted data structure to the files named FILENAME_MATRIX located at gcsMatrixPiecePath (config.h)
 *
 * @param I: (input) ODSE encrypted data structure
 * @return	0 if successful
 */
int ODSE::saveEncrypted_matrix_to_files(MatrixType** I)
{
    int n; 
    TYPE_INDEX col, row, I_col_idx;
    Miscellaneous misc;
    n = MATRIX_COL_SIZE/MATRIX_PIECE_COL_SIZE;
    MatrixType *I_piece = new MatrixType[MATRIX_PIECE_COL_SIZE*MATRIX_ROW_SIZE];
    memset(I_piece,0,MATRIX_PIECE_COL_SIZE*MATRIX_ROW_SIZE);
    for(int i = 0 ; i < n ; i++)
    {
        for(col = 0; col < MATRIX_PIECE_COL_SIZE; col++)
        {
            I_col_idx = col+ (i*MATRIX_PIECE_COL_SIZE);
            for(row = 0 ; row < MATRIX_ROW_SIZE ; row++)
            {
                I_piece[row*MATRIX_PIECE_COL_SIZE+col].byte_data = I[row][I_col_idx].byte_data;
            }
        }
        for(TYPE_INDEX m = 0 ; m < MATRIX_ROW_SIZE; m+=MATRIX_PIECE_ROW_SIZE)
        {
            string filename = misc.to_string(m) + "_" + misc.to_string(i*MATRIX_PIECE_COL_SIZE);
            misc.write_matrix_to_file(filename,gcsEncryptedIdxPath,&I_piece[m*MATRIX_PIECE_COL_SIZE],MATRIX_PIECE_ROW_SIZE,MATRIX_PIECE_COL_SIZE);
        }
    }
    delete[] I_piece;
    return 0;
}

/**
 * Function Name: loadEncrypted_matrix_from_files
 *
 * Description:
 * Load the ODSE encrypted data structure from the file named FILENAME_MATRIX located at gcsMatrixPiecePath (config.h)
 *
 * @param I: (output) ODSE encrypted data structure
 * @return	0 if successful
 */
 int ODSE::loadEncrypted_matrix_from_files(MatrixType** I)
{
    int n; 
    TYPE_INDEX col, row, I_col_idx;
    Miscellaneous misc;
    n = MATRIX_COL_SIZE/MATRIX_PIECE_COL_SIZE;
    MatrixType *I_piece = new MatrixType[MATRIX_PIECE_COL_SIZE*MATRIX_ROW_SIZE];
    memset(I_piece,0,MATRIX_PIECE_COL_SIZE*MATRIX_ROW_SIZE);
    for(int i = 0 ; i < n ; i++)
    {
        for(TYPE_INDEX m = 0 ; m < MATRIX_ROW_SIZE; m+=MATRIX_PIECE_ROW_SIZE)
        {
            string filename = misc.to_string(m) + "_" + misc.to_string(i*MATRIX_PIECE_COL_SIZE);
            misc.read_matrix_from_file(filename,gcsEncryptedIdxPath,&I_piece[m*MATRIX_PIECE_COL_SIZE],MATRIX_PIECE_ROW_SIZE,MATRIX_PIECE_COL_SIZE);
        }
        for(col = 0; col < MATRIX_PIECE_COL_SIZE; col++)
        {
            I_col_idx = col+ (i*MATRIX_PIECE_COL_SIZE);
            for(row = 0 ; row < MATRIX_ROW_SIZE ; row++)
            {
                I[row][I_col_idx].byte_data = I_piece[row*MATRIX_PIECE_COL_SIZE+col].byte_data;
            }
        }
    }
    delete[] I_piece;
    return 0;
}

/**
 * Function Name: setupEncryptedIndex
 *
 * Description:
 * Buid all data structures needed for ODSE (incld. in client and server sides). 
 * The encrypted data structure is stored to file
 *
 * @param rT_W: (output) keyword hash table
 * @param rT_F: (output) file hash table
 * @param lstDummy_column_idx: set of dummy column indexes
 * @param lstFree_row_idx: set of empty row indexes
 * @param pBlockCounterArray: (output) counter for each file
 * @param rFileName: (output) list of distinct files
 * @param path: (intput) location of file collection
 * @param pKey: (input) symmetric keys generated by genMasterKey()
 * @return	0 if successful
 */
int ODSE::setupEncryptedIndex(
		TYPE_GOOGLE_DENSE_HASH_MAP &rT_W,
		TYPE_GOOGLE_DENSE_HASH_MAP &rT_F,
        std::set<TYPE_INDEX> &lstDummy_column_idx,
        std::set<TYPE_INDEX> &lstFree_row_idx,   
        TYPE_COUNTER *pBlockCounterArray,
        vector<string> &rFileNames,
		string path,
		MasterKey *pKey)
{
	TYPE_INDEX row = 0, col = 0;
	std::set<string>::iterator iter;
    int ret;
    
    unsigned char empty_label[6] = "EMPTY";
    unsigned char delete_label[7] = "DELETE";
    hashmap_key_class empty_key = hashmap_key_class(empty_label,6);
    hashmap_key_class delete_key = hashmap_key_class(delete_label,7);
    
	try
    {
        rT_W = TYPE_GOOGLE_DENSE_HASH_MAP(MAX_NUM_KEYWORDS*KEYWORD_LOADING_FACTOR);
        rT_W.max_load_factor(KEYWORD_LOADING_FACTOR);
		rT_W.min_load_factor(0.0);
        rT_W.set_empty_key(empty_key);
		rT_W.set_deleted_key(delete_key);

		rT_F = TYPE_GOOGLE_DENSE_HASH_MAP(MAX_NUM_OF_FILES*KEYWORD_LOADING_FACTOR);
        rT_F.max_load_factor(FILE_LOADING_FACTOR);
		rT_F.min_load_factor(0.0);
		rT_F.set_empty_key(empty_key);
		rT_F.set_deleted_key(delete_key);
        
        lstDummy_column_idx.clear();
        lstFree_row_idx.clear();
        
        for(TYPE_INDEX j = 0 ; j < MATRIX_ROW_SIZE; j++)
           lstFree_row_idx.insert(j);
        for (TYPE_INDEX j = 0 ; j < MATRIX_COL_SIZE*BYTE_SIZE; j++)
            lstDummy_column_idx.insert(j);        
        for(TYPE_INDEX i = 0 ; i < NUM_BLOCKS;i++)
            pBlockCounterArray[i] = 1;

        printf("Scanning whole database first....");
        this->scanDatabase(rFileNames,keywords_dictionary,rT_W,rT_F,path,pKey);

        if(keywords_dictionary.size() >= MAX_NUM_KEYWORDS)
        {
            ret = -1; 
            printf("Error!\n Not enough memory to handle all keywords\n");
            goto exit;
        }
        if (rFileNames.size() >= MAX_NUM_OF_FILES)
        {
            ret = -1;
            printf("Error! Not enough memory to handle all files!\n");
            goto exit;
        }
        printf("OK!\n");
        cout<<"# unique kw: "<<keywords_dictionary.size()<<endl;
        cout<<"# unique files: "<<rFileNames.size()<<endl;

        printf("Creating keyword and file pairs...");
        vector<vector<TYPE_INDEX>> kw_file_pair;
        kw_file_pair.reserve(MATRIX_COL_SIZE*BYTE_SIZE);
        for(TYPE_INDEX col = 0 ; col <MATRIX_COL_SIZE*BYTE_SIZE; col++)
        {
            vector<TYPE_INDEX> tmp;
            kw_file_pair.push_back(tmp);
        }
        this->createKeyword_file_pair(kw_file_pair,rT_W,rT_F,lstFree_row_idx, lstDummy_column_idx, path,pKey);
        printf("OK!\n");
        
        printf(" Creating encrypted matrix...");
        this->createEncrypted_matrix_from_kw_file_pair(kw_file_pair,pBlockCounterArray,pKey);
		printf("OK!\n");
    }
    catch(exception &e)
    {
		cout << "   Error occurred in dynamicsse_index_setup function " << e.what() << endl;
        ret = -1;
        goto exit;
	}
    ret = 0;

exit: 

	return ret;
}

/**
 * Function Name: searchToken
 *
 * Description:
 * generate search token given a keyword being searched
 *
 * @param pSearchToken: (output) generated search token
 * @param keyword: (input) keyword being searched
 * @param rT_W: keyword hash table
 * @param pKey: (input) symmetric keys for data structure encryption
 * @return	0 if successful
 */
int ODSE::searchToken(SEARCH_TOKEN &pSearchToken,
		string keyword,
        TYPE_GOOGLE_DENSE_HASH_MAP &rT_W,
		MasterKey *pKey) 
{
    int ret;
	unsigned char keyword_trapdoor[TRAPDOOR_SIZE] = {'\0'};
    
    ODSE_Trapdoor* odse_trapdoor = new ODSE_Trapdoor();
    /* Generates the trapdoor for the keyword to be searched */
    int keyword_length = strlen(keyword.c_str());
    if((ret = odse_trapdoor->generateTrapdoor_single_input(keyword_trapdoor, TRAPDOOR_SIZE, (unsigned char *)keyword.c_str(), keyword_length, pKey))!=0)
    {
        return -1;
    }
    hashmap_key_class hmap_keyword_trapdoor(keyword_trapdoor, TRAPDOOR_SIZE);
    if(rT_W[hmap_keyword_trapdoor]!=NULL)
        pSearchToken.row_index = rT_W[hmap_keyword_trapdoor];
    else
    {
        pSearchToken.row_index = KEYWORD_NOT_EXIST;
        return -1;
    }
    int selectedIdx = rand() % NUM_SERVERS;
    unsigned char index_vector[MATRIX_ROW_SIZE/BYTE_SIZE];
    memset(index_vector,0,MATRIX_ROW_SIZE/BYTE_SIZE);
    int bit_pos = pSearchToken.row_index  % BYTE_SIZE;
    TYPE_INDEX row_pos = pSearchToken.row_index / BYTE_SIZE;
    BIT_SET(&index_vector[row_pos],bit_pos);
    
    
    unsigned char pseudo_random_number [MATRIX_ROW_SIZE/BYTE_SIZE*(NUM_SERVERS-1)];
    int seed_len = BLOCK_CIPHER_SIZE ; 
	int error = 0;
    unsigned char *pSeed = new unsigned char[seed_len];
    memset(pseudo_random_number,0,(MATRIX_ROW_SIZE/BYTE_SIZE)*(NUM_SERVERS-1));  

    ZZ randBits =  RandomBits_ZZ(MATRIX_ROW_SIZE/BYTE_SIZE*(NUM_SERVERS-1));
    BytesFromZZ(pseudo_random_number,randBits,MATRIX_ROW_SIZE/BYTE_SIZE*(NUM_SERVERS-1));
 
    
    memset(pSearchToken.row_vector[selectedIdx],0,MATRIX_ROW_SIZE/BYTE_SIZE);
   
    TYPE_REGISTER *s1,*s2;
    for(TYPE_INDEX i = 0, j=0 ; i < NUM_SERVERS; i++)
    {
        if(i == selectedIdx)
        {
            continue;
        }
        memcpy(pSearchToken.row_vector[i],&pseudo_random_number[j],MATRIX_ROW_SIZE/BYTE_SIZE);
        for(TYPE_INDEX ii = 0 ; ii< MATRIX_ROW_SIZE/BYTE_SIZE;ii+=sizeof(TYPE_REGISTER))
        {
            s1 = (TYPE_REGISTER*) &pSearchToken.row_vector[i][ii];
            s2 = (TYPE_REGISTER*) &pSearchToken.row_vector[selectedIdx][ii];
            *s2 ^= *s1;
        }
        j+=(MATRIX_ROW_SIZE/BYTE_SIZE);
    }
    for(TYPE_INDEX ii = 0 ; ii< MATRIX_ROW_SIZE/BYTE_SIZE;ii+=sizeof(TYPE_REGISTER))
    {
        s1 = (TYPE_REGISTER*) &index_vector[ii];
        s2 = (TYPE_REGISTER*) &pSearchToken.row_vector[selectedIdx][ii];
        *s2 ^= *s1;        
    }
    
    
    memset(pSeed,0,seed_len);
    memset(pseudo_random_number,0,MATRIX_ROW_SIZE/BYTE_SIZE*(NUM_SERVERS-1));
    memset(keyword_trapdoor,0,TRAPDOOR_SIZE);
    delete odse_trapdoor;
	return 0;
}



/**
 * Function Name: search (for multi-thread)
 *
 * Description:
 * Perform Chor's Pritivate Information Retrieval, given a binary string of search query
 *
 * @param index_vector: (input) seach query
 * @param start: start row (multithread)
 * @param end: end row (multithread)
 * @param I: (input) ODSE encrypted index
 * @param I_prime: (output) PIRed data
 * @return	0 if successful
 */
int ODSE::search(TYPE_INDEX* index_arr, TYPE_INDEX start, TYPE_INDEX end,
                        MatrixType** I,
                        MatrixType* I_prime)
{    
    int ret;
    try
    {
        memset(I_prime,0,MATRIX_COL_SIZE);
        TYPE_REGISTER *s1,*s2;
        for(TYPE_INDEX i = start ; i < end;i++)
        {
            for(TYPE_INDEX j = 0 ; j  < MATRIX_COL_SIZE ; j+=sizeof(TYPE_REGISTER))
            {
                s1 = (TYPE_REGISTER*) &I[index_arr[i]][j];
                s2 = (TYPE_REGISTER*) &I_prime[j];
                *s2 ^= *s1;
            }
        }
    }    
    catch(exception &e)
    {
		cout << "Error occured in getBlock_data function " << e.what() << endl;
        ret = -1;
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}

/**
 * Function Name: update
 *
 * Description:
 * Update the ODSE encrypted data structure, given a adding-file/deleting-file token
 *
 * @param I_prime: (input) block data being updated
 * @param block_index: (input) index of the block being updated
 * @param I: (output) ODSE encrypted data structure after update
 * @return	0 if successful
 */
int ODSE::update(MatrixType* I_prime,              
            TYPE_INDEX block_idx,
            MatrixType** I)
{
    TYPE_INDEX row, col;
    TYPE_INDEX idx;
    TYPE_INDEX begin,end;
    TYPE_INDEX I_prime_bit_idx,I_prime_col_idx;
    TYPE_INDEX bit_position;
    TYPE_INDEX bit_number;
    int ret;
    try
    {
    
        if(ENCRYPT_BLOCK_SIZE>1)
        {
            if(ENCRYPT_BLOCK_SIZE>BYTE_SIZE)
            {
                begin = block_idx*ENCRYPT_BLOCK_SIZE/BYTE_SIZE;
                end = block_idx*ENCRYPT_BLOCK_SIZE/BYTE_SIZE + ENCRYPT_BLOCK_SIZE / BYTE_SIZE;
                idx = 0;
                for (row=0;row<MATRIX_ROW_SIZE; row++)
                {
                    for(col = begin; col < end; col++,idx++)
                    {
                        I[row][col].byte_data = I_prime[idx].byte_data;
                    }
                }
            }
            else
            {
                col = block_idx*ENCRYPT_BLOCK_SIZE /BYTE_SIZE;
                bit_position = (block_idx*ENCRYPT_BLOCK_SIZE)%BYTE_SIZE;
                idx = 0;
                for (row=0;row<MATRIX_ROW_SIZE; row++)
                {
                    for(bit_number = bit_position ;bit_number< bit_position + ENCRYPT_BLOCK_SIZE; bit_number++,idx++)
                    {
                        I_prime_col_idx = idx / BYTE_SIZE;
                        I_prime_bit_idx = idx % BYTE_SIZE;
                        if(BIT_CHECK(&I_prime[I_prime_col_idx].byte_data,I_prime_bit_idx))
                            BIT_SET(&I[row][col].byte_data,bit_number);
                        else
                            BIT_CLEAR(&I[row][col].byte_data,bit_number);
                    }
                }
                
            }
        }
        else
        {
            col = block_idx / (BYTE_SIZE);
            bit_position = block_idx % BYTE_SIZE;
            for (row=0,idx=0;row<MATRIX_ROW_SIZE; row++,idx++)
            {
                I_prime_bit_idx = idx % BYTE_SIZE;
                I_prime_col_idx = idx / BYTE_SIZE;
                if(BIT_CHECK(&I_prime[I_prime_col_idx].byte_data,I_prime_bit_idx))
                    BIT_SET(&I[row][col].byte_data,bit_position);
                else
                    BIT_CLEAR(&I[row][col].byte_data,bit_position);
            }
        }
        /* Iset the counter of this block to+1, set the state of the block to 1.*/
    }
    catch(exception & e)
    {
        cout << "Error occured in add function " << e.what() << endl;
        ret = -1;
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}


/**
 * Function Name: pickRandom_element using NTL
 *
 * Description:
 * Uniformly select an element at random from a set
 *
 * @param random_element: (output) element being picked
 * @param setIdx: (input) set of indices
 * @return	0 if successful
 */
int ODSE::pickRandom_element(TYPE_INDEX &random_element, std::set<TYPE_INDEX> &setIdx)
{
    int ret = 0;
    
    TYPE_INDEX random_idx;
    unsigned char pseudo_random_number [BLOCK_CIPHER_SIZE];
    int seed_len = BLOCK_CIPHER_SIZE ; 
	int error = 0;
   
    unsigned char *pSeed = new unsigned char[seed_len];
    NTL::ZZ tmp;
    NTL::RandomBits(tmp,BLOCK_CIPHER_SIZE*BYTE_SIZE);
    BytesFromZZ(pseudo_random_number,tmp,BLOCK_CIPHER_SIZE);
    
    memcpy(&random_idx,pseudo_random_number,sizeof(random_idx));
    random_idx = random_idx % setIdx.size();
    
    std::set<TYPE_INDEX>::iterator it = setIdx.begin();
    std::advance(it,random_idx);
    random_element = *it;
    
    setIdx.erase(random_element);

exit:
    memset(pseudo_random_number,0,BLOCK_CIPHER_SIZE);
    
    return ret;
}

/**
 * Function Name: getBlock
 *
 * Description:
 * get the block data from the encrypted index, given a block index and the dimension
 *
 * @param index: (input) block index
 * @param dim: dimension (ROW or COL)
 * @param I: (input) ODSE encrypted index
 *  * @param I_prime: (output) block data
 * @return	0 if successful
 */
int ODSE::getBlock( TYPE_INDEX index,    
                        int dim,
                        MatrixType** I,
                        MatrixType* I_prime)
{    
    TYPE_INDEX row, col;
    TYPE_INDEX I_prime_col;
    int ret;
    try
    {
        if(dim==COL)
        {
            TYPE_INDEX I_prime_idx = 0;
            TYPE_INDEX begin;
            TYPE_INDEX end;
            if(ENCRYPT_BLOCK_SIZE >= BYTE_SIZE)
            {
                begin = index * (ENCRYPT_BLOCK_SIZE/BYTE_SIZE);
                end = begin + (ENCRYPT_BLOCK_SIZE/BYTE_SIZE);
                
                for(row = 0 ; row <MATRIX_ROW_SIZE; row++)
                {
                    for(col = begin; col < end;col++,I_prime_idx++)
                    {
                        I_prime[I_prime_idx].byte_data = I[row][col].byte_data;
                    }
                }
            }
            else
            {
                TYPE_INDEX I_bit_idx, I_prime_bit_idx;
                col = (index*ENCRYPT_BLOCK_SIZE) / BYTE_SIZE;
                begin = (index*ENCRYPT_BLOCK_SIZE) % BYTE_SIZE;
                end = begin + ENCRYPT_BLOCK_SIZE;
                for(row = 0 ; row < MATRIX_ROW_SIZE; row++)
                {  
                    for(I_bit_idx = begin; I_bit_idx < end; I_bit_idx++,I_prime_idx++)
                    {
                        I_prime_col = I_prime_idx / BYTE_SIZE;
                        I_prime_bit_idx = I_prime_idx % BYTE_SIZE;
                        
                        if(BIT_CHECK(&I[row][col].byte_data,I_bit_idx))
                            BIT_SET(&I_prime[I_prime_col].byte_data,I_prime_bit_idx);
                        else
                            BIT_CLEAR(&I_prime[I_prime_col].byte_data,I_prime_bit_idx);
                    }
                }
            }
            
            
        }
        else
        {
            memcpy(I_prime,I[index],MATRIX_COL_SIZE);
        }
    }    
    catch(exception &e)
    {
		cout << "Error occured in getBlock_data function " << e.what() << endl;
        ret = -1;
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}

/**
 * Function Name: updateToken
 *
 * Description:
 * Update block data for adding file using precomputed keys 
 *
 * @param update_filename: (input) name of updating file
 * @param path: (input) path of updating file
 * @param indexes: (input) set of lambda chosen random column/block indexes
 * @param I_prime: (output) block_data after updating the file
 * @param S: (input) Stash
 * @param rT_F: (input) file hash table
 * @param rT_W: (input) keyword hash table
 * @param extracted_keyword: (output) uniques keyword being extracted from adding file
 * @param decrypt_key_arr: (input)keys used to decrypt input data
 * @param reencrypt_key_arr: (input) keys used to re-encrypt updated data
 * @param pKey: (input) symmetric key generated by genMasterKey()
 * @return	0 if successful
 */
int ODSE::updateToken(   
                        string update_filename,
                        string path,
                        std::set<TYPE_INDEX> indexes,
                        MatrixType* I_prime,
                        STASH &S,
                        TYPE_GOOGLE_DENSE_HASH_MAP &rT_F,
                        TYPE_GOOGLE_DENSE_HASH_MAP &rT_W,
                        std::set<TYPE_INDEX> &lstDummy_column_idx,
                        std::set<TYPE_INDEX> &lstFree_row_idx,
                        TYPE_KEYWORD_DICTIONARY &extracted_keywords,
                        unsigned char* decrypt_key_arr,
                        unsigned char* reencrypt_key_arr,
                        MasterKey* pKey)
{
    ODSE_Trapdoor *odse_trapdoor = new ODSE_Trapdoor();
    ODSE_KeyGen* odse_keygen = new ODSE_KeyGen(); 
    Miscellaneous misc;
    int bit_position;
    TYPE_INDEX keyword_index;
    TYPE_INDEX row;
    unsigned char keyword_trapdoor[TRAPDOOR_SIZE];
    unsigned char file_trapdoor[TRAPDOOR_SIZE];
    
    TYPE_INDEX row_idx;
    KeywordExtraction* kw_ex = new KeywordExtraction();
    std::set<string>::iterator iter;
    unsigned char *I_bar;
    int ret;
    try
    {   
        //decrypt the downloaded blocks/columns
        MatrixType* decrypted_block = new MatrixType[WRITE_ORAM_LAMBDA * MATRIX_ROW_SIZE*ENCRYPT_BLOCK_SIZE/BYTE_SIZE];
        memset(decrypted_block,0,WRITE_ORAM_LAMBDA * MATRIX_ROW_SIZE*ENCRYPT_BLOCK_SIZE/BYTE_SIZE);
        odse_keygen->enc_dec_preAESKey(decrypted_block,I_prime,decrypt_key_arr,WRITE_ORAM_LAMBDA * MATRIX_ROW_SIZE*ENCRYPT_BLOCK_SIZE/BYTE_SIZE);
        
        
        //process the updated file
        odse_trapdoor->generateTrapdoor_single_input(file_trapdoor, TRAPDOOR_SIZE,	
                                    (unsigned char *)update_filename.c_str(), 
                                    update_filename.size(), pKey);
        I_bar= new unsigned char [MATRIX_ROW_SIZE/BYTE_SIZE];
        memset(I_bar,0,MATRIX_ROW_SIZE/BYTE_SIZE);
        
        string update_filename_with_path = path + update_filename; 
        /* Extract unique keywords */
        if((ret = kw_ex->extractKeywords(extracted_keywords, update_filename_with_path, ""))!=0)
        {
            goto exit;
        }
        hashmap_key_class hmap_file_trapdoor(file_trapdoor,TRAPDOOR_SIZE);
        if(extracted_keywords.size()==0)
        {
            if(rT_F[hmap_file_trapdoor] !=NULL) //delete file
            {
                if(rT_F[hmap_file_trapdoor]!= FILE_IN_STASH)
                {
                    lstDummy_column_idx.insert(rT_F[hmap_file_trapdoor]);
                }
                rT_F.erase(hmap_file_trapdoor);
            }
        }
        else
        {
            for(iter=extracted_keywords.begin();iter != extracted_keywords.end();iter++) 
            {
                string word = *iter;
                int keyword_len = word.size();

                if(keyword_len>0)
                {
                    odse_trapdoor->generateTrapdoor_single_input(keyword_trapdoor, TRAPDOOR_SIZE, 
                                            (unsigned char *)word.c_str(), keyword_len, pKey);
                }
                hashmap_key_class hmap_keyword_trapdoor(keyword_trapdoor, TRAPDOOR_SIZE);
                if(rT_W[hmap_keyword_trapdoor]==NULL)
                {
                    this->pickRandom_element(row_idx,lstFree_row_idx);
                    rT_W[hmap_keyword_trapdoor] = row_idx;
                }
                keyword_index = rT_W[hmap_keyword_trapdoor];
                row = keyword_index / BYTE_SIZE;
                bit_position = keyword_index %BYTE_SIZE;

                BIT_SET(&I_bar[row],bit_position);
                
                word.clear();
            }
            //if the file is currently is in encrypted index
            if(rT_F[hmap_file_trapdoor]<=FILE_NOT_EXIST) 
            {
                lstDummy_column_idx.insert(rT_F[hmap_file_trapdoor]);
                
            }
            else // if the file is in stash
            {
                //remove the stale version of it in stash
                S.erase(S.begin()+(rT_F[hmap_file_trapdoor]-FILE_IN_STASH));
            }
            STASH_DATA s(update_filename,I_bar);
            S.push_back(s);
            rT_F[hmap_file_trapdoor] = FILE_IN_STASH + S.size()-1;
        }
        //get list of dummy indexes in lambda randomly chosen indexes
        
        std::set<TYPE_INDEX> fullColumnIndexes;
        std::map<TYPE_INDEX, TYPE_INDEX> mapIdx;
        TYPE_INDEX k =0;
        for(std::set<TYPE_INDEX>::iterator i = indexes.begin(); i != indexes.end(); ++i,k++)
        {
            for(int j = 0 ; j < ENCRYPT_BLOCK_SIZE; j++)
            {
                fullColumnIndexes.insert((*i)*ENCRYPT_BLOCK_SIZE+j);
                mapIdx[(*i)*ENCRYPT_BLOCK_SIZE+j]=k;
            }
        }
        std::vector<TYPE_INDEX> dummyIndexes;
        std::set_intersection(lstDummy_column_idx.begin(), lstDummy_column_idx.end(),
                              fullColumnIndexes.begin(), fullColumnIndexes.end(),
                              std::back_inserter(dummyIndexes));
        
        MatrixType* writtenColumn = new MatrixType[MATRIX_ROW_SIZE/BYTE_SIZE];
        
        for (std::vector<TYPE_INDEX>::iterator i = dummyIndexes.begin(); i != dummyIndexes.end(); ++i)
        {
            if(S.size()==0)
                break;
            //flush data from stash
            TYPE_INDEX curIdx = *i;
            STASH_DATA curColumn = S.back();
            S.pop_back();
            memcpy(writtenColumn,curColumn.column_data,MATRIX_ROW_SIZE/BYTE_SIZE);
            TYPE_INDEX blockIdx = mapIdx[*i];
            
            this->updateBlock(writtenColumn,&decrypted_block[blockIdx*MATRIX_ROW_SIZE*ENCRYPT_BLOCK_SIZE/BYTE_SIZE],curIdx);
            
            odse_trapdoor->generateTrapdoor_single_input(file_trapdoor, TRAPDOOR_SIZE,	
                                    (unsigned char *)curColumn.ID.c_str(), 
                                    curColumn.ID.size(), pKey);
            hmap_file_trapdoor = hashmap_key_class(file_trapdoor,TRAPDOOR_SIZE);
            rT_F[hmap_file_trapdoor] = curIdx;
            //erase the selected dummy index
            lstDummy_column_idx.erase(curIdx);
        }
        //reencrypt the updated blocks with reenncryption key
        odse_keygen->enc_dec_preAESKey(I_prime,decrypted_block,reencrypt_key_arr,WRITE_ORAM_LAMBDA * MATRIX_ROW_SIZE*ENCRYPT_BLOCK_SIZE/BYTE_SIZE);
        

    }
    catch(exception &e)
    {
		cout << "Error occured in search function " << e.what() << endl;
        ret = -1;
        goto exit;
    }
    ret = 0;

exit:

    // free memory
    delete odse_trapdoor;
    delete kw_ex;
    delete odse_keygen;
    delete I_bar;
   
    return ret;
}


/**
 * Function Name: updateBlock
 * 
 * Description:
 * Update the input block with a new column data
 *
 * @param updating_block: (input) the new data which will be used to update a column data in the input block
 * @param input_block: (input) block going to be updated
 * @param update_idx: (input) the index of columns which will be updated in the input block
 * @return	0 if successful
 */
 
int ODSE::updateBlock(  MatrixType* updating_block,
                        MatrixType* input_block,
                        TYPE_INDEX update_idx)
{
    Miscellaneous misc;
    int bit_position;
    TYPE_INDEX row,col;
    TYPE_INDEX idx,ii,size;
    TYPE_INDEX I_bar_idx, I_bar_row,I_bar_bit_position;
    int ret = 0;
    if(ENCRYPT_BLOCK_SIZE>1)
    {
        for(I_bar_idx = 0 , idx = 0, size = MATRIX_ROW_SIZE*ENCRYPT_BLOCK_SIZE;idx < size; idx+=ENCRYPT_BLOCK_SIZE, I_bar_idx++)
        {
            col=idx/BYTE_SIZE;
            row = idx / ENCRYPT_BLOCK_SIZE;
            I_bar_row = I_bar_idx / BYTE_SIZE;
            I_bar_bit_position = I_bar_idx % BYTE_SIZE;
            
            if(ENCRYPT_BLOCK_SIZE < BYTE_SIZE)
            {
                bit_position = (idx % BYTE_SIZE) + (update_idx % ENCRYPT_BLOCK_SIZE);
    
                if(BIT_CHECK(&updating_block[I_bar_row].byte_data,I_bar_bit_position))
                    BIT_SET(&input_block[col].byte_data,bit_position);
                else
                    BIT_CLEAR(&input_block[col].byte_data,bit_position);
            }
            else
            {
                //Update decrypted I_prime (V) by I_bar
                ii = (update_idx % ENCRYPT_BLOCK_SIZE) / BYTE_SIZE; 
                bit_position = update_idx % BYTE_SIZE;
                
                if(BIT_CHECK(&updating_block[I_bar_row].byte_data,I_bar_bit_position))
                    BIT_SET(&input_block[row*(ENCRYPT_BLOCK_SIZE/BYTE_SIZE)+ii].byte_data,bit_position);
                else
                    BIT_CLEAR(&input_block[row*(ENCRYPT_BLOCK_SIZE/BYTE_SIZE)+ii].byte_data,bit_position);
            }
        }
    }
    else
    {
        memcpy(input_block,updating_block,MATRIX_ROW_SIZE/BYTE_SIZE);
        
    }
    return ret;
}

