/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description: Client-side functionalities in ODSE with XOR-based PIR            %
% (Function descriptions are presented individually (see below)                  %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2016-09-13      Functions created                %
%--------------------------------------------------------------------------------*/

#include "Client_ODSE.h"
#include "config.h"
#include "ODSE_KeyGen.h"
#include "string.h"
#include <sstream>	
#include "Miscellaneous.h"

#include "ODSE.h"
#include "math.h"

#include "zmq.hpp"
#include "ODSE_Trapdoor.h"

using namespace zmq;

#include "struct_thread_getData.h"



std::set<TYPE_INDEX> Client_ODSE::lstDummy_column_idx;
std::set<TYPE_INDEX> Client_ODSE::lstFree_row_idx;

Client_ODSE::Client_ODSE()
{
    
    
}

Client_ODSE::~Client_ODSE()
{
    
}

/**
 * Function Name: initMemory
 *
 * Description:
 * Initialize memory for variables used at the client
 *
 * @return	0 if successful
 */
int Client_ODSE::initMemory()
{
    
    I_prime = new zz_p*[NUM_SERVERS];
    for (int s = 0 ; s < NUM_SERVERS; s++)
    {
        I_prime[s] = new zz_p[WRITE_ORAM_LAMBDA*MATRIX_ROW_SIZE];
    }
    
    ready = true;
    
    search_data = new MatrixType*[NUM_SERVERS];
    for(int i = 0 ; i < NUM_SERVERS; i++)
    {
        search_data[i] = new MatrixType[MATRIX_COL_SIZE];
        memset(search_data[i],0,MATRIX_COL_SIZE);
    }
    
    search_result = new zz_p*[NUM_SERVERS];
    for(int s = 0 ; s < NUM_SERVERS; s++)
    {
        search_result[s]  = new zz_p[MATRIX_COL_SIZE /(FF_SIZE/BYTE_SIZE)];
    }
    
    mat_search_res = new MatrixType[MATRIX_COL_SIZE];
    memset(mat_search_res,0,MATRIX_COL_SIZE);
    
        
    serializedSearchIdxVector = new unsigned char*[NUM_SERVERS];
    for(int s = 0 ; s < NUM_SERVERS; s++)
    {
        serializedSearchIdxVector[s] = new unsigned char[MATRIX_ROW_SIZE*FF_SIZE/BYTE_SIZE];
    }
    
    this->update_data = new unsigned char*[NUM_SERVERS];
    for(int i = 0 ; i < NUM_SERVERS; i++)
    {
        this->update_data[i] = new unsigned char [WRITE_ORAM_LAMBDA * MATRIX_ROW_SIZE*FF_SIZE/BYTE_SIZE];
        memset(update_data[i],0, WRITE_ORAM_LAMBDA* MATRIX_ROW_SIZE*FF_SIZE/BYTE_SIZE);
    }
        
      
    return 0;
}

/**
 * Function Name: genMaster_key
 *
 * Description:
 * Generate symmetric keys used to encrypt ODSE data structure, files, and hash tables
 *
 * @return	0 if successful
 */
int Client_ODSE::genMaster_key()
{
    
    ODSE_KeyGen *odse_key = new ODSE_KeyGen();
    this->masterKey = new MasterKey();
    int ret;
    odse_key->genMaster_key(this->masterKey);
    
    ret = 0;
    
exit:
    delete odse_key;
    return ret;
}

/**
 * Function Name: loadState
 *
 * Description:
 * Loat previous state into memory
 *
 * @return	0 if successful
 */
int Client_ODSE::loadState()
{
    // Load keys
    printf("   Loading master key...");
    this->masterKey = new MasterKey();

    string key_loc = gcsClientStatePath + "key1";
    Miscellaneous::read_file_cpp(this->masterKey->key1,BLOCK_CIPHER_SIZE,key_loc);
     
    //Load client state
    unsigned char empty_label[6] = "EMPTY";
    unsigned char delete_label[7] = "DELETE";
      hashmap_key_class empty_key = hashmap_key_class(empty_label,6);
    hashmap_key_class delete_key = hashmap_key_class(delete_label,7);
    printf("OK!\n");
    printf("    Loading hash tables...");
    T_W = TYPE_GOOGLE_DENSE_HASH_MAP(MAX_NUM_KEYWORDS*KEYWORD_LOADING_FACTOR);
    T_W.max_load_factor(KEYWORD_LOADING_FACTOR);
    T_W.min_load_factor(0.0);
    T_W.set_empty_key(empty_key);
    T_W.set_deleted_key(delete_key);

    T_F = TYPE_GOOGLE_DENSE_HASH_MAP(MAX_NUM_OF_FILES*KEYWORD_LOADING_FACTOR);
    T_F.max_load_factor(FILE_LOADING_FACTOR);
    T_F.min_load_factor(0.0);
    T_F.set_empty_key(empty_key);
    T_F.set_deleted_key(delete_key);
        
    T_W.clear();
    T_F.clear();


    TYPE_COUNTER total_keywords_files[2];
    Miscellaneous::read_array_from_file(FILENAME_TOTAL_KEYWORDS_FILES,gcsClientStatePath,total_keywords_files,2);
        
    Miscellaneous::readHash_table(T_W,gcsKwHashTable,gcsClientStatePath,total_keywords_files[0]);
    Miscellaneous::readHash_table(T_F,gcsFileHashTable,gcsClientStatePath,total_keywords_files[1]);
    
    lstDummy_column_idx.clear();
    lstFree_row_idx.clear();

    Miscellaneous::read_list_from_file(gcsListFreeFileIdx,gcsClientStatePath,lstDummy_column_idx);
    Miscellaneous::read_list_from_file(gcsListFreeKwIdx,gcsClientStatePath,lstFree_row_idx);
    
    printf("OK!\n");
    
            
    printf("   Loading Stash...");
    this->S.clear();
    Miscellaneous::read_stash_from_file(FILENAME_STASH,gcsClientStatePath,this->S);
    printf("OK!\n");
    
    
    printf("\nFinished!\n");
    printf("Size of keyword hash table: \t\t\t %zu \n",T_W.bucket_count());
    printf("Load factor of keyword hash table: \t\t %3.10f \n",T_W.load_factor());
    printf("# kw in hash table: \t\t\t\t %5.0f \n",T_W.load_factor()*T_W.bucket_count());
    
    printf("Size of file hash table: \t\t\t %zu \n",T_F.bucket_count());
    printf("Load factor of file hash table: \t\t %3.10f \n",T_F.load_factor());
    printf("# files in hash table: \t\t\t\t %5.0f \n",T_F.load_factor()*T_F.bucket_count());
        
    cout<<"Size of list dummy column idx: "<<lstDummy_column_idx.size()<<endl;
    cout<<"Size of list free row idx: "<<lstFree_row_idx.size()<<endl;
    
    cout<<"Stash size: "<<this->S.size();

    return 0;
}


/**
 * Function Name: saveState
 *
 * Description:
 * Save current state from memorty to disk
 *
 * @return	0 if successful
 */
int Client_ODSE::saveState()
{
     
    //write keys to file
    printf("   Writing hash key...");
    
    string key_loc = gcsClientStatePath + "key1";
    Miscellaneous::write_file_cpp(key_loc,this->masterKey->key1,BLOCK_CIPHER_SIZE);
        
    printf("OK!\n");
    
    printf("   Writing hash tables...");
    
    Miscellaneous::writeHash_table(T_W,gcsKwHashTable,gcsClientStatePath);
    Miscellaneous::writeHash_table(T_F,gcsFileHashTable,gcsClientStatePath);
    
    Miscellaneous::write_list_to_file(gcsListFreeFileIdx,gcsClientStatePath,lstDummy_column_idx);
    Miscellaneous::write_list_to_file(gcsListFreeKwIdx,gcsClientStatePath,lstFree_row_idx);
        
    printf("OK!\n");
        
    printf("   Writing Stash...");
    Miscellaneous::write_stash_to_file(FILENAME_STASH,gcsClientStatePath,this->S);
    printf("OK!\n");
    
        
    printf("   Writing total keywords and files...");
    TYPE_COUNTER total_keywords_files[2] = {this->T_W.load_factor()*T_W.bucket_count(), this->T_F.load_factor()*T_F.bucket_count()} ;
    Miscellaneous::write_array_to_file(FILENAME_TOTAL_KEYWORDS_FILES,gcsClientStatePath,total_keywords_files,2);
    printf("OK!\n");
    
    return 0;
    
}

/**
 * Function Name: createEncryptedIndex
 *
 * Description:
 * Create the ODSE encrypted index
 *
 * @return	0 if successful
 */
int Client_ODSE::createEncryptedIndex()
{
    ODSE* odse = new ODSE();
    int ret;
    vector<string> files_input;

    Miscellaneous misc;

    ODSE_KeyGen* odse_keygen  = new ODSE_KeyGen();
    try
    {
        printf("1. Generating hash table key......");
        this->genMaster_key();
        printf("OK!\n");
        
        files_input.reserve(MAX_NUM_OF_FILES);
        printf("2. Setting up data structure......\n");
        if((ret = odse->setupEncryptedIndex( this->T_W,this->T_F, this->lstDummy_column_idx, this->lstFree_row_idx,
                                    files_input,gcsFilepath,
                                    this->masterKey))!=0)
        {
            goto exit;
        }
        printf("\nFINISHED!\n");
        printf("Size of keyword hash table: \t\t\t %zu \n",this->T_W.bucket_count());
        printf("Load factor of keyword hash table: \t\t %3.10f \n",this->T_W.load_factor());
        printf("# keywords extracted: \t\t\t\t %5.0f \n",this->T_W.load_factor()*T_W.bucket_count());
        printf("Size of file hash table: \t\t\t %zu \n",this->T_F.bucket_count());
        printf("Load factor of file hash table: \t\t %3.10f \n",this->T_F.load_factor());
        printf("# files extracted: \t\t\t\t %5.0f \n",this->T_F.load_factor()*T_F.bucket_count());
        
        
        printf("3. Saving states...");
        
        
        saveState();
        printf("OK!\n");


        printf("\n---ENCRYPTED INDEX CONSTRUCTION COMPLETED!---\n");
        this->sendEncryptedIndex();
        
    }
    catch (exception &ex)
    {
        ret = -1;
        goto exit;
    }
    ret =0;
exit:
    delete odse_keygen;
    files_input.clear();
    delete odse;
    return ret;
}

/**
 * Function Name: sendEncryptedIndex
 *
 * Description: Send the encrypted index to the server
 *
 * @return	0 if successful
 */
int Client_ODSE::sendEncryptedIndex()
{
    Miscellaneous misc;
    char choice = ' ';
    do
    {
        cout << " UPLOAD ENCRYPTED INDEX TO SERVER? (y/n)  \n **** ONLY SAY 'y' IF CLIENT AND SERVERS ARE DEPLOYED IN DIFFERENT MACHINES!! *** \n";
        cin >> choice;
        choice = tolower(choice);
    }while( !cin.fail() && choice!='y' && choice!='n' );
    if(choice=='y')
    {
            
        printf("1. Sending Matrix I to server(s)...");
        for( int s = 0 ; s < NUM_SERVERS ; s++)
        {
            int n = MATRIX_COL_SIZE / MATRIX_PIECE_COL_SIZE;        
            for(int i = 0 ; i < n ; i++)
            {
                for(TYPE_INDEX m = 0 ; m < MATRIX_ROW_SIZE; m+=MATRIX_PIECE_ROW_SIZE)
                {
                    int curServer = SERVER_ID[s]-1;
                    string filename = "S" + misc.to_string(curServer) + "_" + misc.to_string(m) + "_" + misc.to_string(i*MATRIX_PIECE_COL_SIZE);
                    this->sendFile(s,filename,gcsEncryptedIdxPath,CMD_SEND_ENCRYPTED_INDEX);
                }
            }
        }
        printf("OK!\n");
    }
    for( int s = 0 ; s < NUM_SERVERS ; s++)
        this->sendCommandOnly(s, CMD_LOADSTATE);
    return 0;
}

/**
 * Function Name: sendFile
 *
 * Description:
 * send a (physical) file to the server *
 *
 * @param filename: (input) name of sending file
 * @param number: (input) location of sending file
 * @param SENDING_TYPE: (input) type of files (e.g., encrypted index, etc.)
 * @return	0 if successful
 */
int Client_ODSE::sendFile(int server_id, string filename, string path, int SENDING_TYPE)
{
    int ret;
    int n; 
    
    FILE* finput = NULL;
    unsigned char buffer_in[SOCKET_BUFFER_SIZE];
	unsigned char buffer_out[SOCKET_BUFFER_SIZE];
	
    off_t filesize, offset;
    off_t size_sent = 0;
    string filename_with_path = path + filename;
    
    zmq::context_t context(1);
    zmq::socket_t socket(context,ZMQ_REQ);
    string PEER_ADDRESS = SERVER_ADDR[server_id] + SERVER_PORT[server_id];
    try
    {
        printf("   Opening file...");
        if( ( finput = fopen(filename_with_path.c_str(), "rb" ) ) == NULL )
        {
            printf( "Error! File not found \n" );
            ret = -1;
            goto exit;
        }
        if( ( filesize = lseek( fileno( finput ), 0, SEEK_END ) ) < 0 )
        {
            perror( "lseek" );
            ret = -1;
            goto exit;
        }
        if( fseek( finput, 0, SEEK_SET ) < 0 )
        {
            printf("fseek(0,SEEK_SET) failed\n" );
            ret = -1;
            goto exit;
        }
        printf("OK!\n");
        
        printf("   Connecting to server...");
        
        socket.connect (PEER_ADDRESS.c_str());
        printf("OK!\n");
        
        printf("   Sending file sending command...");
        memset(buffer_out,0,SOCKET_BUFFER_SIZE);
        memcpy(buffer_out,&SENDING_TYPE,sizeof(SENDING_TYPE));
        socket.send(buffer_out,SOCKET_BUFFER_SIZE);
        socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
        printf("OK!\n");
        
        printf("   Sending file name...");
        socket.send((unsigned char*) filename.c_str(),strlen(filename.c_str()));
        printf("OK!\n");
        socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
        
        printf("   Sending file data...");
        memset(buffer_out,0,SOCKET_BUFFER_SIZE);
        memcpy(buffer_out,&filesize,sizeof(size_t));
        socket.send(buffer_out,SOCKET_BUFFER_SIZE);
        socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
        
        // 6.2 Read file block by block and write to the destination
        size_sent = 0;
        for( offset = 0; offset < filesize; offset += SOCKET_BUFFER_SIZE )
        {
            n = ( filesize - offset > SOCKET_BUFFER_SIZE ) ? SOCKET_BUFFER_SIZE : (int)
                ( filesize - offset );
            if( fread( buffer_in, 1, n, finput ) != (size_t) n )
            {
                printf( "read input file error at block %d",n);
                break;
            }
            if(offset + n ==filesize)
                socket.send(buffer_in,n,0);
            else
                socket.send(buffer_in,n,ZMQ_SNDMORE);
            size_sent += n;
            if(size_sent % 10485760 == 0)
                printf("%jd / %jd sent \n",size_sent,filesize);
        }
        fclose(finput);
        socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
        printf("OK!\t\t\t %jd bytes sent\n",size_sent);
    }
    catch (exception &ex)
    {
        ret = -1;
        goto exit;
    }
    ret = 0;
exit:

    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
	memset(buffer_out,0,SOCKET_BUFFER_SIZE);
    socket.disconnect(PEER_ADDRESS.c_str());
    socket.close();
    
    return ret;
    
}

/**
 * Function Name: sendCommandOnly
 *
 * Description: send a command-only to let the server load/save data into memory
 *
 * @return	0 if successful
 */
int Client_ODSE::sendCommandOnly(int server_id, int cmd)
{
    zmq::context_t context(1);
    zmq::socket_t socket(context,ZMQ_REQ);
    string PEER_ADDRESS = SERVER_ADDR[server_id] + SERVER_PORT[server_id];
    socket.connect(PEER_ADDRESS);
    socket.send(&cmd,sizeof(cmd),0);
    unsigned char buffer_in[SOCKET_BUFFER_SIZE];
    socket.recv(buffer_in,SOCKET_BUFFER_SIZE,0);
    socket.disconnect(PEER_ADDRESS);
}

 
/**
 * Function Name: searchKeyword
 *
 * Description:
 * search a keyword
 *
 * @param keyword: (input) keyword would like to search
 * @param number: (output) number of files that the searching keyword appear in
 * @return	0 if successful
 */
int Client_ODSE::searchKeyword(string keyword, TYPE_COUNTER &number)
{
    ODSE* odse = new ODSE();
    int ret;
    SearchToken tau;
    unsigned long elapsed;
    std::set<TYPE_INDEX> lstFile_id;
    
    ODSE_KeyGen* odse_keygen = new ODSE_KeyGen();
    try
    {
        if(ready == false)
        {
            printf("Encrypted index is not constructed/load yet, please build it first!\n");
            return 0;
        }
        
        printf("\n\n Searching \"%s\" ....\n\n", keyword.c_str());
        /*Generate the token for this keyword using SrchToken procedure*/        
        printf("1. Generating keyword token...");
       if( (ret = odse->searchToken(  tau,
                            keyword,
                            this->T_W,
                            this->masterKey)) != 0 )
        {
            printf("Error! SearchToken generation failed\n");
            goto exit;
        }
        //get Search data from n servers
        for(int s = 0 ; s < NUM_SERVERS; s++)
        {
            //serialize it first
            odse->serializeFFElementVector(serializedSearchIdxVector[s],tau.row_vector[s],MATRIX_ROW_SIZE);
        }
        printf("OK!\n");
        if(tau.row_index == KEYWORD_NOT_EXIST)
        {
            printf("Keyword not exist!\n");
            goto exit;
        }
        /* 2. Peform the search...*/
        
        for(int s = 0 ; s < NUM_SERVERS; s++)
        {
            get_data_param[s].server_id = s;
            get_data_param[s].data = (unsigned char*)search_data[s];
            get_data_param[s].idx_vector = serializedSearchIdxVector[s];
            pthread_create(&thread_getData[s],NULL,&Client_ODSE::thread_getSearchData_func,(void*)&get_data_param[s]);
        }
        for(int s = 0 ; s < NUM_SERVERS; s++)
        {
            pthread_join(thread_getData[s], NULL);
        }
        //process search_data
        for(int s = 0 ; s < NUM_SERVERS; s++)
        {
            odse->deserializeFFElementVector((unsigned char*)search_data[s],search_result[s],MATRIX_COL_SIZE/(FF_SIZE/BYTE_SIZE));
        }
        // SSS recover
        for(TYPE_INDEX j = 0 , col = 0 ; j < MATRIX_COL_SIZE/(FF_SIZE/BYTE_SIZE);j++,col+=(FF_SIZE/BYTE_SIZE))
        {
            zz_p shares[NUM_SERVERS];
            for(int i = 0 ; i < NUM_SERVERS ; i++)
            {
                shares[i] = search_result[i][j];
            }
            zz_p res = odse->simpleRecover(shares,2*PRIVACY_LEVEL+1);
            memcpy((unsigned char*)&search_data[0][col],&res,FF_SIZE/BYTE_SIZE);
        }
        for(TYPE_INDEX ii=0; ii<MATRIX_COL_SIZE; ii++)
        {
                for(int bit_number = 0 ; bit_number<BYTE_SIZE; bit_number++)
                    if(BIT_CHECK(&search_data[0][ii].byte_data,bit_number))
                        lstFile_id.insert(ii*BYTE_SIZE+bit_number);
        }
        //filter dummy columns and include data in stash for final search result
        vector<TYPE_INDEX> dummyIndexes;
        
        std::set_intersection(lstDummy_column_idx.begin(), lstDummy_column_idx.end(),
                              lstFile_id.begin(), lstFile_id.end(),
                              std::back_inserter(dummyIndexes));
        for(std::vector<TYPE_INDEX>::iterator i = dummyIndexes.begin(); i != dummyIndexes.end() ; ++i)
        {
            lstFile_id.erase((*i));
        }
        vector<string> files_in_stash;
        for(int i = 0 ; i < this->S.size(); i++)
        {
            unsigned char* curData = S[i].column_data;
            if(BIT_CHECK(&curData[tau.row_index/BYTE_SIZE],tau.row_index%BYTE_SIZE))
                files_in_stash.push_back(S[i].ID);
        }
        //write result to file
        std::ofstream output;
        output.open(gcsClientStatePath+FILENAME_SEARCH_RESULT);
       
        for(std::set<TYPE_INDEX>::iterator i = lstFile_id.begin(); i != lstFile_id.end() ; i++)
        {
            output << *i << " ";
        }
        output<<endl;
        
        for(int i = 0 ; i < files_in_stash.size(); i++)
        {
            output<< files_in_stash[i]<<" ";
        }
        number = files_in_stash.size() + lstFile_id.size();
    }
    catch (exception &ex)
    {
        ret = -1;
        goto exit;
    }
    ret = 0 ;
    
exit:
    memset(&tau,0,sizeof(SearchToken));
    delete odse;

    delete odse_keygen;

    return ret;
 }

/**
 * Function Name: sendSearch_query
 *
 * Description:
 * Get search data from a server using Chor's PIR
 * @param server_id: (input) ID of the server
 * @param row_vector: (input) search query
 * @param I_prime: (output)  search data from this server
 * @return	0 if successful
 */
int Client_ODSE::sendSearch_query(int server_id, unsigned char* row_vector, unsigned char* I_prime) 
{
    int cmd;
    unsigned char buffer_in[SOCKET_BUFFER_SIZE] = {'\0'};
    unsigned char buffer_out[SOCKET_BUFFER_SIZE] = {'\0'};
    int ret;
    
    zmq::context_t context(1);
    zmq::socket_t socket(context,ZMQ_REQ);
    
    TYPE_INDEX serialized_buffer_len = MATRIX_COL_SIZE;
    MatrixType serialized_buffer[serialized_buffer_len]; 
    string PEER_ADDRESS = SERVER_ADDR[server_id] + SERVER_PORT[server_id];
    
    try
    {   
        memset(serialized_buffer,0,serialized_buffer_len);
        
        
        //printf("Connecting to the server... ");
        socket.connect(PEER_ADDRESS.c_str());
        
        //printf("   2.2. Sending request command...");
        cmd = CMD_SEARCH_OPERATION;
        memset(buffer_out,0,SOCKET_BUFFER_SIZE);
        memcpy(buffer_out,&cmd,sizeof(cmd));
        socket.send(buffer_out,SOCKET_BUFFER_SIZE);
        socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
        
        //printf("   2.3. Sending RequestIndex token..."); 
        socket.send(row_vector,MATRIX_ROW_SIZE*FF_SIZE/BYTE_SIZE);
        
        //printf("   2.4. Receiving data..."); 
        socket.recv(serialized_buffer,serialized_buffer_len);
        
        /* deserialize */
        memcpy(I_prime,serialized_buffer,MATRIX_COL_SIZE);
    }
    catch(exception &ex)
    {
        ret = -1;
        goto exit;
    }
    ret = 0;

exit:
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    memset(buffer_out,0,SOCKET_BUFFER_SIZE);
    socket.disconnect(PEER_ADDRESS.c_str());
    socket.close();
    return ret;
}



/**
 * Function Name: downloadColumnBlock
 *
 * Description:
 * Get a block data from a server
 * @param server_id: (input) ID of the server
 * @param indexes: (input) list of random indexes 
 * @param I_prime: (output) the desired column
 * @return	0 if successful
 */
int Client_ODSE::downloadColumnBlock(int server_id, std::set<TYPE_INDEX> indexes, unsigned char* I_prime) 
{
    int cmd;
    unsigned char buffer_in[SOCKET_BUFFER_SIZE] = {'\0'};
    unsigned char buffer_out[SOCKET_BUFFER_SIZE] = {'\0'};
    int ret;
    unsigned char* uchar_indexes = new unsigned char[sizeof(TYPE_INDEX)*WRITE_ORAM_LAMBDA];
    memset(uchar_indexes,0,sizeof(TYPE_INDEX) * WRITE_ORAM_LAMBDA);
    
    std::set<TYPE_INDEX>::iterator i = indexes.begin();
    int j = 0;
    for(i = indexes.begin(); i != indexes.end(); ++i)
    {
        TYPE_INDEX tmp = *i;
        memcpy(&uchar_indexes[j*sizeof(TYPE_INDEX)], &tmp ,sizeof(TYPE_INDEX));
        j++;
    }
    
    zmq::context_t context(1);
    zmq::socket_t socket(context,ZMQ_REQ);
    TYPE_INDEX serialized_buffer_len = WRITE_ORAM_LAMBDA*(MATRIX_ROW_SIZE*FF_SIZE)/BYTE_SIZE;
    
    MatrixType* serialized_buffer = new MatrixType[serialized_buffer_len]; //consist of data and block state
    string PEER_ADDRESS = SERVER_ADDR[server_id] + SERVER_PORT[server_id];

    try
    {   
        memset(serialized_buffer,0,serialized_buffer_len);
        
        //printf("   2.1. Connecting to the server... ");
        socket.connect(PEER_ADDRESS.c_str());
       
        //printf("   2.2. Sending request command...");
        cmd = CMD_DOWNLOAD_COLUMN_BLOCK;
        memset(buffer_out,0,SOCKET_BUFFER_SIZE);
        memcpy(buffer_out,&cmd,sizeof(cmd));
        socket.send(buffer_out,SOCKET_BUFFER_SIZE);
        socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
        
        //printf("   2.3. Sending RequestIndex token..."); 
        socket.send(uchar_indexes,sizeof(TYPE_INDEX)*WRITE_ORAM_LAMBDA);
        
        //printf("   2.4. Receiving data..."); 
        socket.recv(serialized_buffer,serialized_buffer_len);
        
        /* deserialize */
        memcpy(I_prime,serialized_buffer,WRITE_ORAM_LAMBDA*(MATRIX_ROW_SIZE*FF_SIZE)/BYTE_SIZE);
    }
    catch(exception &ex)
    {
        ret = -1;
        goto exit;
    }
    ret = 0;

exit:
    delete uchar_indexes;
    delete serialized_buffer;
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    memset(buffer_out,0,SOCKET_BUFFER_SIZE);
    socket.disconnect(PEER_ADDRESS.c_str());
    socket.close();
    return ret;
}

/**
 * Function Name: uploadColumnBlock
 *
 * Description:
 * Send a block data to a server to update the encrypted data structure
 * @param server_id: (input) ID of the server
 * @param indexes: (input) list of random indexes
 * @param I_prime: (input) the desired column
 * @return	0 if successful
 */
int Client_ODSE::uploadColumnBlock(int server_id, std::set<TYPE_INDEX> indexes, unsigned char* I_prime)
 {
    int cmd;
    Miscellaneous misc;
    unsigned char buffer_in[SOCKET_BUFFER_SIZE] = {'\0'};
    unsigned char buffer_out[SOCKET_BUFFER_SIZE] = {'\0'};
    unsigned char* uchar_indexes = new unsigned char[sizeof(TYPE_INDEX)*WRITE_ORAM_LAMBDA];
    memset(uchar_indexes,0,sizeof(TYPE_INDEX) * WRITE_ORAM_LAMBDA);
    
    int ret;
    string filename_temp_with_path;
    
    zmq::context_t context(1);
    zmq::socket_t socket(context,ZMQ_REQ);
    string PEER_ADDRESS = SERVER_ADDR[server_id] + SERVER_PORT[server_id];
    TYPE_INDEX serialized_buffer_len = WRITE_ORAM_LAMBDA*(MATRIX_ROW_SIZE*FF_SIZE)/BYTE_SIZE;
    std::set<TYPE_INDEX>::iterator i = indexes.begin();
    int j = 0;
    for(i = indexes.begin(); i != indexes.end(); ++i)
    {
        TYPE_INDEX tmp = *i;
        memcpy(&uchar_indexes[j*sizeof(TYPE_INDEX)], &tmp ,sizeof(TYPE_INDEX));
        j++;
    }
    try
    {
        //printf("   2.1. Connecting to the server... ");
        socket.connect(PEER_ADDRESS.c_str());
        
        //printf("   2.2. Sending update block command...");
        cmd = CMD_UPLOAD_COLUMN_BLOCK;
        memset(buffer_out,0,SOCKET_BUFFER_SIZE);
        memcpy(buffer_out,&cmd,sizeof(cmd));
        socket.send(buffer_out,SOCKET_BUFFER_SIZE);
        socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
        
        //printf("   2.3. Sending column/block indexes..."); 
        socket.send(uchar_indexes,sizeof(TYPE_INDEX)*WRITE_ORAM_LAMBDA);
        socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
        
        //printf("   2.4. Sending block data..."); 
        /* send serialized data */
        socket.send((unsigned char*)I_prime,serialized_buffer_len,0);
        socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
    }
    catch (exception &ex)
    {
        ret = -1;
        goto exit;
    }
    ret = 0;
exit:
    delete uchar_indexes;
    socket.disconnect(PEER_ADDRESS.c_str());
    socket.close();
    memset(buffer_in,0,sizeof(buffer_in));
    memset(buffer_out,0,sizeof(buffer_out));
    filename_temp_with_path.clear();
    return ret;
}

int Client_ODSE::updateFile(string filename, string path)
{
    
    Miscellaneous misc;
    ODSE* odse = new ODSE();
    int ret;
    TYPE_KEYWORD_DICTIONARY extracted_keywords;
    std::set<TYPE_INDEX> selectedIdx;
    selectedIdx.clear();
    stringstream new_filename_with_path;
    string s;
  
    ODSE_KeyGen* odse_keygen = new ODSE_KeyGen();

    try
    {
        // 1. Select lambda random column/block indexes
        while(selectedIdx.size() < WRITE_ORAM_LAMBDA)
        {
            long rand;
            RandomBits(rand,sizeof(TYPE_INDEX));
            rand = rand % NUM_BLOCKS;
            selectedIdx.insert(rand);
        }
        // 2. Download lambda columns / blocks
        
        printf("Getting lambda columns/blocks from t+1 servers...\n");
                
        for(int i = 0 ; i < PRIVACY_LEVEL+1; i++)
        {
            memset(update_data[i],0,WRITE_ORAM_LAMBDA * MATRIX_ROW_SIZE*FF_SIZE/BYTE_SIZE);
        }
        THREAD_GETDATA get_data_param_new[NUM_SERVERS];
        for(int s = 0 ; s <NUM_SERVERS;s++)
        {
            get_data_param_new[s].data = update_data[s];
            get_data_param_new[s].column_indexes = selectedIdx;
            get_data_param_new[s].server_id = s;
            pthread_create(&thread_getData[s],NULL,&Client_ODSE::thread_downloadData_func,(void*)&get_data_param_new[s]);
        
        }
        for(int s = 0 ; s < PRIVACY_LEVEL+1;s++)
        { 
            pthread_join( thread_getData[s], NULL);
        }
        //deserialize
        for(int s = 0 ; s < PRIVACY_LEVEL+1 ; s++)
        {
            odse->deserializeFFElementVector(update_data[s],this->I_prime[s],WRITE_ORAM_LAMBDA * MATRIX_ROW_SIZE);
        }
        
        printf("Peforming update...\n");
        odse->updateToken(filename,path,selectedIdx,this->I_prime,this->S,this->T_F,this->T_W,this->lstDummy_column_idx, this->lstFree_row_idx,extracted_keywords,this->masterKey);
        
        
        //serialize again
         for(int s = 0 ; s < NUM_SERVERS ; s++)
        {
            odse->serializeFFElementVector(update_data[s],this->I_prime[s],WRITE_ORAM_LAMBDA * MATRIX_ROW_SIZE);
        }
        
        printf("Uploading to servers...\n");
        for(int s = 0 ; s < NUM_SERVERS ; s++)
        {
            this->get_data_param[s].column_indexes = selectedIdx;
            this->get_data_param[s].data = this->update_data[s];
            this->get_data_param[s].server_id = s;
            pthread_create(&thread_getData[s],NULL,&Client_ODSE::thread_uploadData_func,(void*)&this->get_data_param[s]);
        }
        for (int s = 0 ; s < NUM_SERVERS; s++)
        {
            pthread_join( thread_getData[s], NULL);
        }
        if(T_F.load_factor()*T_F.bucket_count()==MAX_NUM_OF_FILES)
        {
            printf("The index is full!. Please do not add new file in the next update and increase the encrypted index size!!");
        }
        printf("\nDONE!\n\n");
        
    }
    catch(exception &ex)
    {
        ret = -1;
        goto exit;
    }    
    ret = 0;

exit:
    extracted_keywords.clear();

    delete odse;

    delete odse_keygen;
    return ret;
}

void *Client_ODSE::thread_getSearchData_func(void* param)
{
    THREAD_GETDATA* opt = (THREAD_GETDATA*) param;
    Client_ODSE* call = new Client_ODSE();
    call->sendSearch_query(opt->server_id, opt->idx_vector, opt->data);
    delete call;
    pthread_exit((void*)opt);
}

void *Client_ODSE::thread_downloadData_func(void* param)
{
    THREAD_GETDATA* opt = (THREAD_GETDATA*) param;
    Client_ODSE* call = new Client_ODSE();
    call->downloadColumnBlock(opt->server_id,opt->column_indexes,opt->data);
    delete call;
    pthread_exit((void*)opt);
}

void *Client_ODSE::thread_uploadData_func(void* param)
{
    THREAD_GETDATA* opt = (THREAD_GETDATA*) param;
    Client_ODSE* call = new Client_ODSE();
    call->uploadColumnBlock(opt->server_id,opt->column_indexes,opt->data);
    delete call;
    pthread_exit((void*)opt);
}


