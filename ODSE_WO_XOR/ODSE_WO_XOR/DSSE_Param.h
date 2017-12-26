/*-------------------------------------------------------------------------------%
% This software was written by CR/RTC3.2-NA as part of the Project XXXXXXX.      %
%  Copyright (C) CR/RTC3.2-NA, Robert Bosch LLC, 2016. All rights reserved.      %
%                                                                                %
%  See LICENSE.txt FILE for licensing details.                                   %
%                                                                                %
%                                                                                %
%  It is strongly recommended that before you distribute any code you contact    %
%  the open source officer responsible within your organization to request an    %
%  open source license and permission to distribute this                         %
%  software.                                                                     %
%                                                                                %
% Version: 1.00                                                                  %
%                                                                                %
% Description:    Configuration parameters for DSSE with Chor's PIR   		     %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2016-09-13      File created                     %
%--------------------------------------------------------------------------------*/


#ifndef DSSE_PARAM_H
#define DSSE_PARAM_H
#include "DSSE_Hashmap_Key_Class.h"	


#define ENCRYPT_BLOCK_SIZE 128
//#define LOAD_FROM_DISK

#define MAX_NUM_OF_FILES 6272       	    // Define the maximum number of files for the scheme
#define MAX_NUM_KEYWORDS 6272 				// Define the maximum number of keywords for the scheme


#define MULTI_THREAD

//static const string noFile = "50000";


#define INTEL_AES_NI

#define SERVER_ID 0
#define NUM_SERVERS 2


#include <stdio.h>
#include <string.h>	
#include <stdlib.h>
#include <cerrno>								
#include <algorithm>						
#include <functional>						
#include <iostream>						
#include <fstream>	
#include <sstream>	
#include <bitset>
#include <vector>
#include <iterator>	
#include <dirent.h>	
#include <sys/types.h>			
#include <sys/stat.h>		
#include <unistd.h>
#include <set>												
#include <sparsehash/dense_hash_map>				
#include <boost/algorithm/string/split.hpp>		
#include <boost/algorithm/string.hpp>
#include "climits"
#include <chrono>


#include "NTL/ZZ.h"

using namespace NTL;


const string PEER_ADDRESSES[NUM_SERVERS] = {"tcp://127.0.0.1:4433", "tcp://127.0.0.1:4432"};



static const string gcsDataStructureFilepath = "../example/" + to_string(MAX_NUM_OF_FILES) + "_" + to_string(MAX_NUM_KEYWORDS) + "/data_structure/client/";
static const string gcsMatrixPiecePath = "../example/"  + to_string(MAX_NUM_OF_FILES) + "_" + to_string(MAX_NUM_KEYWORDS) + "/data_structure/server/";


static const string gcsFilepath = "../example/input/";			                // path of files directory (Absolute path recommended if enabling ENCRYPT_PHYSICAL_FILE)
static const string gcsEncFilepath = "../example/encrypted_input/";				// path of encrypted files directory (Absolute path recommended if enabling ENCRYPT_PHYSICAL_FILE)
static const string gcsUpdateFilepath = "../example/update/";			        // path of files directory (Absolute path recommended if enabling ENCRYPT_PHYSICAL_FILE)
static const string gcsEncryptedUpdateFilepath = "../example/encrypted_update/";


//Client- Service Define

#define MATRIX_PIECE_COL_SIZE  MATRIX_COL_SIZE //128 //2560         //in byte
#define MATRIX_PIECE_ROW_SIZE MATRIX_ROW_SIZE//MATRIX_ROW_SIZE //20000         // in bit





//#define LOAD_PREBUILT_DATA_MODE                   // enable it to load the previously created data structures
#define UPLOAD_DATA_STRUCTURE_MANUALLY_MODE       // enable it to manually copy previously created data structure to the server.



#define COL 1
#define ROW 2
using namespace std;	
using google::dense_hash_map;
//using tr1::hash;
using namespace boost::algorithm;

#define ZERO_VALUE 0
#define ONE_VALUE 1	

#define BYTE_SIZE 8	
#define RDRAND_RETRY_NUM 10
#define TRAPDOOR_SIZE 16   
#define NONCE_SIZE 12
#define BLOCK_CIPHER_SIZE 16
															

#define MATRIX_ROW_SIZE MAX_NUM_KEYWORDS

//Loading factors in hash table before resizing
#define FILE_LOADING_FACTOR 0.5
#define KEYWORD_LOADING_FACTOR 0.5



#define MATRIX_COL_SIZE ((MAX_NUM_OF_FILES/BYTE_SIZE)*2)	
	
#define MAC_NAME "MAC"

#define NUM_BLOCKS (MATRIX_COL_SIZE*BYTE_SIZE/ENCRYPT_BLOCK_SIZE)	

#define ENCRYPT_BLOCK_SIZE2 4



//Commands for Client - Server interaction
#define CMD_SEND_DATA_STRUCTURE         0x000010
#define CMD_ADD_FILE_PHYSICAL           0x00000F
#define CMD_DELETE_FILE_PHYSICAL        0x000040
#define CMD_SEARCH_OPERATION            0x000020

#define CMD_REQUEST_BLOCK_DATA          0x000050
#define CMD_REQUEST_SEARCH_DATA         0x000051
#define CMD_REQUEST_UPDATE_DATA         0x000052

#define CMD_UPDATE_BLOCK_DATA           0x000060
#define CMD_SUCCESS                     "CMD_OK"

#define REQUEST_TIMEOUT                 -76

//define the default filename of some data structures in DSSE scheme
#define FILENAME_MATRIX                 "data_structure"
#define FILENAME_GLOBAL_COUNTER         "global_counter"
#define FILENAME_BLOCK_STATE_MATRIX     "block_state_mat"
#define FILENAME_BLOCK_STATE_ARRAY     "block_state_arr"
#define FILENAME_BLOCK_COUNTER_ARRAY     "block_counter_arr"
#define FILENAME_I_PRIME                "i_prime"
#define FILENAME_SEARCH_RESULT          "search_result"

#define KEYWORD_NOT_EXIST MAX_NUM_KEYWORDS+1
#define FILE_NOT_EXIST MAX_NUM_OF_FILES+1

//buffer size of each packet for sending / receiving 
#define SOCKET_BUFFER_SIZE              256

//MACROS
#define BIT_READ(character, position, the_bit)	((*the_bit = *character & (1 << position)))	
#define BIT_SET(character, position) ((*character |= 1 << position))	
#define BIT_CLEAR(character, position) ((*character &= ~(1 << position)))
#define BIT_TOGGLE(character, position)	((*character ^= 1 << position))
#define BIT_CHECK(var,pos) !!((*var) & (1<<(pos)))


static const string gcsKwHashTable = "kw_hashtable";
static const string gcsFileHashTable = "file_hashtable";
static const string gcsListFreeFileIdx = "lstFreeFileIdx";
static const string gcsListFreeKwIdx = "lstFreeKwIdx";
static const string gcsListDummyColIdx = "lstDummyColIdx";


// Delimiter separating unique keywords from files 		
const char* const delimiter = "`-=[]\\;\',./~!@#$%^&*()+{}|:\"<>? \n\t\v\b\r\f\a";	
												
typedef unsigned long long int TYPE_COUNTER;
typedef unsigned long long int TYPE_INDEX;
typedef dense_hash_map<hashmap_key_class,TYPE_INDEX,hashmap_key_class,hashmap_key_class> TYPE_GOOGLE_DENSE_HASH_MAP;
typedef std::set<string> TYPE_KEYWORD_DICTIONARY;



static TYPE_KEYWORD_DICTIONARY keywords_dictionary;

#define time_now std::chrono::high_resolution_clock::now()

static std::set<TYPE_INDEX> setSelected_idx;


typedef unsigned long long int TYPE_REGISTER;
#endif
