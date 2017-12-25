/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description:   Server-side functionalities in ODSE with XOR-based PIR          %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description		                 %
%   Thang Hoang                 2016-09-13      Functions created                %
%--------------------------------------------------------------------------------*/


#ifndef SERVER_ODSE_H
#define SERVER_ODSE_H

#include <MasterKey.h>
#include <config.h>
#include <struct_MatrixType.h>

#include <zmq.hpp>
#include "struct_thread_PIRComputation.h"
using namespace zmq;
class Server_ODSE
{
private:
    
    int numThreads;
    
    //Encrypted index 
    MatrixType** I;
    
    TYPE_INDEX* one_idx_search_array;
    TYPE_INDEX one_idx_search_n;

    THREAD_PIR_COMPUTATION* pir_args;
    MatrixType** PIR_search_output = new MatrixType*[numThreads];

    pthread_t* thread_computePIR;

public:
    Server_ODSE(int numThreads);
    ~Server_ODSE();
      
    int start(int server_id);

    int loadState();
    int saveState();
    int getEncryptedIndex(zmq::socket_t &socket);
    
    
    
    int getColumnBlock(zmq::socket_t &socket);
    int updateColumnBlock(zmq::socket_t &socket);
  


    //PIR computations
    int search(zmq::socket_t & socket);
    //multi-thread
    static void* thread_computePIR_func(void* args);

};

#endif // SERVER_ODSE_H
