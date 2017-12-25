/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description:    Configuration parameters for ODSE with XOR-based PIR  	     %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2016-09-13      File created                     %
%--------------------------------------------------------------------------------*/


#ifndef ODSE_PARAM_H
#define ODSE_PARAM_H

#include "ODSE_Hashmap_Key_Class.h"	
#include <stdio.h>
#include <string.h>	
#include <stdlib.h>
#include <algorithm>						
#include <functional>						
#include <iostream>						
#include <fstream>	
#include <sstream>	
#include <bitset>
#include <vector>
#include <iterator>	
#include <dirent.h>	
#include <sys/stat.h>		
#include <unistd.h>
#include <set>												
#include <sparsehash/dense_hash_map>				
#include <boost/algorithm/string/split.hpp>		
#include <boost/algorithm/string.hpp>
#include "climits"
#include <chrono>
#include <map>

#include "NTL/ZZ_p.h"
#include "NTL/ZZ.h"
#include "NTL/ZZ_pX.h"
#include "NTL/lzz_p.h"
#include "NTL/GF2X.h"
#include "NTL/tools.h"
#include "NTL/GF2XFactoring.h"
#include "NTL/GF2E.h"
#include <NTL/WordVector.h>
#include <NTL/vector.h>
#include "NTL/GF2EX.h"
static const unsigned long P = 512124571219774627; // 59 bit prime // to use NTL optimized code, p<=2^60
#define NP_BITS 59      // number of bits of P
#define FF_SIZE 64      // finite field size (by bit), should be multiplication of 8 and larger than log2(P)



#define BYTE_SIZE 8

#define MAX_NUM_OF_FILES 12544
#define MAX_NUM_KEYWORDS MAX_NUM_OF_FILES

#define WRITE_ORAM_LAMBDA 30


#define NUM_SERVERS 3
#define PRIVACY_LEVEL 1 // <= NUM_SERVERS - 1 

const int SERVER_ID[NUM_SERVERS] ={1,2,3};

const std::string SERVER_ADDR[NUM_SERVERS] = {"tcp://localhost:", "tcp://localhost:", "tcp://localhost:"};
const std::string SERVER_PORT[NUM_SERVERS] = {"5555","5556", "5557"};

const long long int vandermonde[NUM_SERVERS] = {3,-3+P,1};
//const long long int vandermonde[NUM_SERVERS] = {7, -21+P, 35, -35+P, 21, -7+P, 1};

/** Vandermonde Values for Different Number of Servers (7, 5, 3)*/
//{7, -21+P, 35, -35+P, 21, -7+P, 1};//{5, -10+P, 10, -5+P, 1};//{3, -3+P, 1};




using namespace NTL;
using namespace std;	
using google::dense_hash_map;
using namespace boost::algorithm;




static const string gcsClientStatePath = "../data/state/";
static const string gcsEncryptedIdxPath = "../data/EIDX/";
static const string gcsFilepath = "../data/DB/";			                // path of input database
static const string gcsUpdateFilepath = "../data/Update/";                  // Path of updated file





#define MATRIX_PIECE_COL_SIZE  (MATRIX_COL_SIZE) //MATRIX_COL_SIZE 
#define MATRIX_PIECE_ROW_SIZE MATRIX_ROW_SIZE
#define BLOCK_PIECE_SIZE MATRIX_PIECE_COL_SIZE / (FF_SIZE/BYTE_SIZE)



#define COL 1
#define ROW 2

#define ZERO_VALUE 0
#define ONE_VALUE 1


#define TRAPDOOR_SIZE 16   
#define BLOCK_CIPHER_SIZE 16
#define MATRIX_ROW_SIZE MAX_NUM_KEYWORDS

//Loading factors in hash table before resizing
#define FILE_LOADING_FACTOR 0.5
#define KEYWORD_LOADING_FACTOR 0.5



#define MATRIX_COL_SIZE ((MAX_NUM_OF_FILES/BYTE_SIZE)*2)	
#define NUM_BLOCKS (MATRIX_COL_SIZE*BYTE_SIZE/FF_SIZE)	


//Commands for Client - Server interaction
#define CMD_SEND_ENCRYPTED_INDEX         0x000010
#define CMD_LOADSTATE                   0x000011
#define CMD_SAVESTATE                   0x000012
#define CMD_SEARCH_OPERATION            0x000020
#define CMD_DOWNLOAD_COLUMN_BLOCK       0x000050
#define CMD_UPLOAD_COLUMN_BLOCK         0x000060
#define CMD_SUCCESS                     "CMD_OK"




//define the default filename of some data structures in ODSE
#define FILENAME_TOTAL_KEYWORDS_FILES   "keywords_files"
#define FILENAME_SEARCH_RESULT          "search_result"
#define FILENAME_STASH                  "stash"

#define KEYWORD_NOT_EXIST MAX_NUM_KEYWORDS+1
#define FILE_NOT_EXIST MATRIX_COL_SIZE*BYTE_SIZE+1
#define FILE_IN_STASH MATRIX_COL_SIZE*BYTE_SIZE+2

 
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


// Delimiter separating unique keywords from files 		
const char* const delimiter = "`-=[]\\;\',./~!@#$%^&*()+{}|:\"<>? \n\t\v\b\r\f\a";	

typedef unsigned long  TYPE_COUNTER;
typedef unsigned long  TYPE_INDEX;
typedef dense_hash_map<hashmap_key_class,TYPE_INDEX,hashmap_key_class,hashmap_key_class> TYPE_GOOGLE_DENSE_HASH_MAP;
typedef std::set<string> TYPE_KEYWORD_DICTIONARY;

#include "struct_StashData.h"
typedef vector<STASH_DATA> STASH;

static TYPE_KEYWORD_DICTIONARY keywords_dictionary;

#define time_now std::chrono::high_resolution_clock::now()

typedef unsigned long long int TYPE_REGISTER;
#endif
