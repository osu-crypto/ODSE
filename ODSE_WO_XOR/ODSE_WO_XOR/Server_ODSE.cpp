/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description:   Server-side functionalities in ODSE with XOR-based PIR          %
% (Function descriptions are presented individually (see below)                  %
%                                                                                %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2016-09-13      Functions created                %
%--------------------------------------------------------------------------------*/

#include "Server_ODSE.h"
#include "config.h"
#include "ODSE_KeyGen.h"

#include "Miscellaneous.h"

#include "ODSE.h"
#include "zmq.hpp"
#include <sys/socket.h>
#include <sys/types.h>
#include "struct_thread_PIRComputation.h"
using namespace zmq;

Server_ODSE::Server_ODSE(int numThreads)
{
    TYPE_INDEX i;
    
    /* Allocate memory for encrypted index (matrix) */
    this->I = new MatrixType *[MATRIX_ROW_SIZE];
    for (i = 0; i < MATRIX_ROW_SIZE;i++ )
    {
        this->I[i] = new MatrixType[MATRIX_COL_SIZE];
    }
    
    
    this->one_idx_search_array = new TYPE_INDEX[MATRIX_ROW_SIZE];
    this->one_idx_search_n = 0;
    
    
    this->numThreads = numThreads;
 
    this->pir_args = new THREAD_PIR_COMPUTATION[numThreads];
    
    PIR_search_output = new MatrixType*[numThreads];
    for(int i = 0 ; i < numThreads; i++)
    {
        PIR_search_output[i] = new MatrixType[MATRIX_COL_SIZE];
    }
    thread_computePIR = new pthread_t[numThreads];
    
}

Server_ODSE::~Server_ODSE()
{
    
}

/**
 * Function Name: loadState()
 *
 * Description:
 * Load the previous state into the memory
 *
 * @return	0 if successful
 */
int Server_ODSE::loadState()
{
    printf("   Loading encrypted index...");
    ODSE* odse = new ODSE();
    
    odse->loadEncrypted_matrix_from_files(this->I);
    printf("OK!\n");

    delete odse;
}


/**
 * Function Name: saveState()
 *
 * Description:
 * Save the current sate into memory
 *
 * @return	0 if successful
 */
int Server_ODSE::saveState()
{
    printf("   Saving encrypted index...");
    ODSE* odse = new ODSE();
    odse->saveEncrypted_matrix_to_files(this->I);
    printf("OK!\n");
    
}

/**
 * Function Name: start()
 *
 * Description:
 * Start the ODSE program at server side (e.g., open and listen port)
 *
 * @param socket: (output) opening socket
 * @return	0 if successful
 */
int Server_ODSE::start(int server_id)
{
    int ret;
    unsigned char buffer[SOCKET_BUFFER_SIZE];
    zmq::context_t context(1);
    zmq::socket_t socket(context,ZMQ_REP);
    string filename = to_string(MAX_NUM_OF_FILES);    
    string stats;
    string PEER_ADDRESS = "tcp://*:" + SERVER_PORT[server_id];
    socket.bind(PEER_ADDRESS.c_str());
    
    do
    {
        printf("Waiting for request......\n\n");
        while(!socket.connected());
        
        /* 1. Read the command sent by the client to determine the job */
        socket.recv(buffer,SOCKET_BUFFER_SIZE,ZMQ_RCVBUF);
        
        int cmd;
        memcpy(&cmd,buffer,sizeof(cmd));
        
        switch(cmd)
        {
        case CMD_SEND_ENCRYPTED_INDEX:
            printf("Get Encrypted Index...!\n");
            socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
            this->getEncryptedIndex(socket);
            break;
        case CMD_LOADSTATE:
            this->loadState();
            socket.send(CMD_SUCCESS,sizeof(CMD_SUCCESS),0);
            break;
        case CMD_SAVESTATE:
            this->saveState();
            socket.send(CMD_SUCCESS,sizeof(CMD_SUCCESS),0);
            break;
        case CMD_SEARCH_OPERATION:
            printf("Search Requested....!\n");
            socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
            this->search(socket);
            break;
        
       case CMD_UPLOAD_COLUMN_BLOCK:
            printf("Update Columns of Encrypted Index...!\n");
            socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
            this->updateColumnBlock(socket);
            break;
        case CMD_DOWNLOAD_COLUMN_BLOCK:
            printf("Download Columns of Encrypted Index...!\n");
            socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
            this->getColumnBlock(socket);
            break;
        
        
        default:
            break;
        }
        
    }while(1);

    printf("Server ended \n");
    ret = 0;

    memset(buffer,0,SOCKET_BUFFER_SIZE);
    return ret;
}

/**
 * Function Name: getEncryptedIndex
 *
 * Description:
 * Process the encrypted data structure block data sent by the client
 *
 * @param socket:  opening socket
 * @return	0 if successful
 */
int Server_ODSE::getEncryptedIndex(zmq::socket_t& socket)
{
    Miscellaneous misc;
    unsigned char buffer_in[SOCKET_BUFFER_SIZE] = {'\0'};
    int ret, len;
    len = 0;
    FILE* foutput = NULL;
    size_t size_received = 0 ;
    size_t file_in_size;
    
    int64_t more;
    size_t more_size = sizeof(more);

    
    printf("1. Receiving file name....");
    socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
    string filename((char*)buffer_in);
    printf("OK!\t\t\t %s \n",filename.c_str());
    string filename_with_path = gcsEncryptedIdxPath + filename;
    
    printf("2. Opening the file...");
    if((foutput =fopen(filename_with_path.c_str(),"wb+"))==NULL)
    {
        printf("Error! File opened failed!\n");
        ret = -1;
        goto exit;
    }
    printf("OK!\n");
    socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
    
    printf("3. Receiving file content");
    
    // Receive the file size in bytes first
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
    
    memcpy(&file_in_size,buffer_in,sizeof(size_t));
    printf(" of size %zu bytes...",file_in_size);
    socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
    
    // Receive the file content
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    size_received = 0;
    while(size_received<file_in_size)
    {
        len = socket.recv(buffer_in,SOCKET_BUFFER_SIZE,0);
        if(len == 0)
            break;
        size_received += len;
        if(size_received >= file_in_size)
        {
            fwrite(buffer_in,1,len-(size_received-file_in_size),foutput);
            break;
        }
        else
        {
            fwrite(buffer_in,1,len,foutput);
        }
        socket.getsockopt(ZMQ_RCVMORE,&more,&more_size);
        if(!more)
            break;
    }
    fclose(foutput);
    socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
    
    printf("OK!\n\t\t %zu bytes received\n",size_received);
    
    printf("4. Updating memory...");
    
    printf("OK!\n");
    ret = 0;

exit:
    return ret ;
}


/**
 * Function Name: search
 *
 * Description:
 * XOR-based PIR computation for search request from the client
 *
 * @param socket: (output) opening socket
 * @return 0 if successful
 */
int Server_ODSE::search(zmq::socket_t & socket)
{
    Miscellaneous misc;
    ODSE *odse = new ODSE();
   
    unsigned char buffer_in[SOCKET_BUFFER_SIZE] = {'\0'};
    unsigned char buffer_out[SOCKET_BUFFER_SIZE] = {'\0'};
    int ret = 0;
    
    unsigned char index_vector[MATRIX_ROW_SIZE/BYTE_SIZE];
    memset(index_vector,0,MATRIX_ROW_SIZE/BYTE_SIZE);
    
    TYPE_INDEX serialized_buffer_len = MATRIX_COL_SIZE;
auto start = time_now;
auto end = time_now;

    MatrixType* serialized_buffer = new MatrixType[serialized_buffer_len]; 
    memset(serialized_buffer,0,serialized_buffer_len);
start = time_now;
    printf("1.  Receiving row vector requested....");
    socket.recv(index_vector,MATRIX_ROW_SIZE/BYTE_SIZE);
    printf("OK!\n");
    
    //convert row vector to list of index of 1's value
    this->one_idx_search_n = 0;
    for(TYPE_INDEX i  = 0 ; i < MATRIX_ROW_SIZE/BYTE_SIZE;i++)
    {
        for(int bit_pos = 0 ; bit_pos < BYTE_SIZE;bit_pos++)
        {
            if(BIT_CHECK(&index_vector[i],bit_pos))
            {
                this->one_idx_search_array[this->one_idx_search_n] = i*BYTE_SIZE+bit_pos;
                this->one_idx_search_n++;
            }
        }
    }
end = time_now;
cout<<"Receive row vector time: "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()<<" ns"<<endl;
        
    /* Get the block data requested by the client by PIR */
start = time_now;
  
    // Multi-thread for PIR computation
    int step = ceil((double)this->one_idx_search_n/(double)numThreads);
    int endIdx;
    
    for(int i = 0, startIdx = 0; i < numThreads , startIdx < this->one_idx_search_n; i ++, startIdx+=step)
    {
        if(startIdx+step > this->one_idx_search_n)
            endIdx = this->one_idx_search_n;
        else
            endIdx = startIdx+step;
            
        this->pir_args[i] = THREAD_PIR_COMPUTATION(this->I,PIR_search_output[i],startIdx, endIdx, this->one_idx_search_array);
        
        pthread_create(&thread_computePIR[i], NULL, &Server_ODSE::thread_computePIR_func, (void*)&pir_args[i]);
		
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(i, &cpuset);
        pthread_setaffinity_np(thread_computePIR[i], sizeof(cpu_set_t), &cpuset);
    }
    for(int i = 0, startIdx = 0 ; i < numThreads , startIdx < one_idx_search_n; i ++, startIdx+=step)
    {
        pthread_join(thread_computePIR[i],NULL);
    }
    //XOR all together
    memset(serialized_buffer,0,serialized_buffer_len);
    TYPE_REGISTER *s1,*s2;
    for(int i = 0 ; i < numThreads;i++)
    {
        for(TYPE_INDEX j = 0 ; j < MATRIX_COL_SIZE; j+=sizeof(TYPE_REGISTER))
        {
            s1 = (TYPE_REGISTER*) &this->PIR_search_output[i][j];
            s2 = (TYPE_REGISTER*) &serialized_buffer[j];
            *s2 ^= *s1;
        }
    }
end = time_now;
cout<<"Perform PIR computation time: "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()<<" ns"<<endl;

start = time_now;        
    /* Send block data requested by the client */
    socket.send(serialized_buffer,serialized_buffer_len);
    ret = 0 ;
end = time_now;
cout<<"Send serialized data time: "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()<<" ns"<<endl;
    
    delete serialized_buffer;
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    memset(buffer_out,0,SOCKET_BUFFER_SIZE);
    delete odse;
    return ret ; 
}

void *Server_ODSE::thread_computePIR_func(void* args)
{
    THREAD_PIR_COMPUTATION* opt = (THREAD_PIR_COMPUTATION*) args;
    
    ODSE odse;
    //std::cout << " CPU # " << sched_getcpu() << "\n";
    odse.search(opt->one_idx_arr,opt->start,opt->end,opt->input,opt->output);
    pthread_exit((void*)opt);
}

/**
 * Function Name: updateColumnBlock
 *
 * Description:
 * Update columns with new data sent from client
 *
 * @param socket: (output) opening socket
 * @return	0 if successful
 */
int Server_ODSE::updateColumnBlock(zmq::socket_t& socket)
{
    auto start = time_now;
    auto end = time_now;
    Miscellaneous misc;
    ODSE *odse = new ODSE();
    
    unsigned char buffer_in[SOCKET_BUFFER_SIZE] = {'\0'};
    unsigned char buffer_out[SOCKET_BUFFER_SIZE] = {'\0'};
    
    unsigned char* uchar_indexes = new unsigned char[sizeof(TYPE_INDEX)*WRITE_ORAM_LAMBDA];
    memset(uchar_indexes,0,sizeof(TYPE_INDEX) * WRITE_ORAM_LAMBDA);
    TYPE_INDEX indexes[WRITE_ORAM_LAMBDA];
    
    
    
    TYPE_INDEX serialized_buffer_len = WRITE_ORAM_LAMBDA * (MATRIX_ROW_SIZE*ENCRYPT_BLOCK_SIZE)/BYTE_SIZE;
    MatrixType* serialized_buffer = new MatrixType[serialized_buffer_len]; 
    
    start = time_now; 
    printf("Receiving block index....");
    socket.recv(uchar_indexes,sizeof(TYPE_INDEX)*WRITE_ORAM_LAMBDA);
    memcpy(indexes,uchar_indexes,sizeof(TYPE_INDEX)*WRITE_ORAM_LAMBDA);
    socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));
    end = time_now;
    cout<<std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()<<" ns"<<endl;

        
    /* Receive block data sent by the client */
    memset(serialized_buffer,0,serialized_buffer_len);
    
    start = time_now;
    printf("Receiving block data....");
    socket.recv(serialized_buffer,serialized_buffer_len);
    end = time_now;
    cout<<std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()<<" ns"<<endl;
    
    /* Update the received I' */
    printf("Calling Update function...");

    start = time_now;
    for(int i = 0 ; i < WRITE_ORAM_LAMBDA; i++)
    {
        odse->update(&serialized_buffer[i*(MATRIX_ROW_SIZE*ENCRYPT_BLOCK_SIZE)/BYTE_SIZE],indexes[i],this->I);
    }
    end = time_now;
    cout<<std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()<<" ns"<<endl;
        
    socket.send((unsigned char*)CMD_SUCCESS,sizeof(CMD_SUCCESS));

    delete serialized_buffer;
    delete odse;
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    memset(buffer_out,0,SOCKET_BUFFER_SIZE);
    return 0 ; 
}

/**
 * Function Name: getColumnBlock
 *
 * Description:
 * Send Columns/Blocks to the client
 *
 * @param socket: (output) opening socket
 * @return	0 if successful
 */
int Server_ODSE::getColumnBlock(zmq::socket_t & socket)
{
    Miscellaneous misc;
    ODSE *odse = new ODSE();
   
    unsigned char buffer_in[SOCKET_BUFFER_SIZE] = {'\0'};
    unsigned char buffer_out[SOCKET_BUFFER_SIZE] = {'\0'};
    
    unsigned char* uchar_indexes = new unsigned char[sizeof(TYPE_INDEX)*WRITE_ORAM_LAMBDA];
    memset(uchar_indexes,0,sizeof(TYPE_INDEX) * WRITE_ORAM_LAMBDA);
    TYPE_INDEX indexes[WRITE_ORAM_LAMBDA];
    
    TYPE_INDEX serialized_buffer_len;
auto start = time_now;
auto end = time_now;

    serialized_buffer_len = WRITE_ORAM_LAMBDA*(MATRIX_ROW_SIZE*ENCRYPT_BLOCK_SIZE)/BYTE_SIZE;
    
    MatrixType* serialized_buffer = new MatrixType[serialized_buffer_len]; //consist of data and block state
    memset(serialized_buffer,0,serialized_buffer_len);
    
    start = time_now;
    printf("Receiving index requested....");
    socket.recv(uchar_indexes,sizeof(TYPE_INDEX)*WRITE_ORAM_LAMBDA);    
    memcpy(indexes,uchar_indexes,sizeof(TYPE_INDEX)*WRITE_ORAM_LAMBDA);
    end = time_now;
    cout<<std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()<<" ns"<<endl;
    
    // Get the block data requested by the client
    start = time_now;
    
    for(int i = 0 ; i < WRITE_ORAM_LAMBDA ; i++)
    {
        odse->getBlock(indexes[i],COL,this->I,&serialized_buffer[i*(MATRIX_ROW_SIZE*ENCRYPT_BLOCK_SIZE)/BYTE_SIZE]);
    }
    end = time_now;
    cout<<"Get Block data locally time: "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end-start).count()<<" ns"<<endl;
    
    // Send block data requested by the client
    socket.send(serialized_buffer,serialized_buffer_len,0);
    
    delete serialized_buffer;
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    memset(buffer_out,0,SOCKET_BUFFER_SIZE);
    delete odse;
    return 0 ; 
}
