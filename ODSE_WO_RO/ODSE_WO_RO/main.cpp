/*-------------------------------------------------------------------------------%
% Version: 1.00                                                                  %
%                                                                                %
% Description:   main file of ODSE with XOR-based PIR                            %
%                                                                                %
% History Information                                                            %
%   Person                      Date            Comment                          %
%--------------------------------------------------------------------------------%
%   Name               			YYYY-MM-DD    	Description	         %
%   Thang Hoang                 2016-09-13      Functions created                %
%--------------------------------------------------------------------------------*/


#include <stdio.h>
#include <Server_ODSE.h>
#include <config.h>
#include <Miscellaneous.h>
#include <unistd.h>
#include <Client_ODSE.h>
#include <config.h>

#include <unistd.h>
#include <thread>


unsigned int nthreads = std::thread::hardware_concurrency();

void printMenu();

string exec(const char* cmd);

bool fexists(string filename_with_path)
{
  ifstream ifile(filename_with_path.c_str());
  if(!ifile.is_open())
      return false;
  return true;
}

int main_server(int serverID, int numThreads)
{
    Server_ODSE* server = new Server_ODSE(numThreads);
    server->start(serverID); 
}
int main_client()
{
    auto start = time_now;
    auto end = time_now;
	string search_word;
    Miscellaneous misc;
    std::string update_loc = gcsUpdateFilepath;
    string updating_filename;
    string updateFilename_with_path;
    TYPE_COUNTER search_result;
    Client_ODSE*  client_odse = new Client_ODSE();
    client_odse->initMemory();
    int tmp;
    string str_keyword;
    while (1)
    {
        int selection =-1;
        do
        {
            printMenu();
            cout<<"Select your choice: ";
            while(!(cin>>selection))
            {
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(),'\n');
                cout<<"Invalid input. Try again: ";
            }
            
        }while(selection < 0 && selection >4);
        switch(selection)
        {
             case 0:
                client_odse->loadState();
                for(int s = 0 ; s < NUM_SERVERS; s++)
                    client_odse->sendCommandOnly(s,CMD_LOADSTATE);
                break;
            case 1:
                start = time_now;
                client_odse->createEncryptedIndex();
                end = time_now;
                cout<<"BUILINDG TIME: "<<std::chrono::duration_cast<std::chrono::milliseconds>(end-start).count()<<" ms"<<endl;
                break;
            case 2:
                //str_keyword = "the";
                cout<<"Keyword search: ";
                cin>>str_keyword;
                std::transform(str_keyword.begin(),str_keyword.end(),str_keyword.begin(),::tolower);
                search_result =0;
                client_odse->searchKeyword(str_keyword,search_result);
                cout<<" Keyword *"<<str_keyword<<"* appeared in "<<search_result <<" files"<<endl;
                cout<<" Check the file named ``" << FILENAME_TOTAL_KEYWORDS_FILES <<"'' for detailed filenames!"<<endl;
                
                break;
            case 3:
                cout<<"Specify the filename want to update: ";
                cin>>updating_filename;
                updateFilename_with_path = gcsUpdateFilepath + updating_filename;
                
                if(!fexists(updateFilename_with_path))
                {
                    cout<<endl<<"File not found! Please put/check if the file exists in *data/update* folder!!!"<<endl;
                    break;
                }
                else
                {
                    client_odse->updateFile(updating_filename,gcsUpdateFilepath);
                }
                break;
            case 4:
                client_odse->saveState();
                for(int s = 0 ; s < NUM_SERVERS ; s++)
                    client_odse->sendCommandOnly(s,CMD_SAVESTATE);
                exit(1);
                break;
            default:
                break;
        }
    }
}
int main(int argc, char **argv)
{  

    setbuf(stdout,NULL);
    zz_p::init(P);
    int choice;
    
    cout << "CLIENT(1) or SERVER(2): ";
	cin >> choice;
	cout << endl;
	
	if(choice == 2)
	{
		int serverNo;
        int selectedThreads;
		cout << "Enter the Server No: (1..."<<NUM_SERVERS<<"): ";
		cin >> serverNo;
        serverNo--;
		cin.clear();
		cout << endl;
        
        do
        {
            cout<< "How many computation threads to use? (1-"<<nthreads<<"): ";
            cin>>selectedThreads;
		}while(selectedThreads>nthreads);
        
		main_server(serverNo,selectedThreads);
	}
	else if (choice == 1)
	{
		cout << "SERVER READY? (Press ENTER to Continue)";
		cin.ignore();
		cin.ignore();
		cin.clear();
		cout << endl;
		
        main_client();
	}
	else
	{
		cout << "COME ON!!" << endl;
	}
    
    
    return 0;
    
}

void printMenu()
{
    cout<<"---------------"<<endl<<endl;
    cout<<"0. Load previous state"<<endl;
    cout<<"1. (Re)build encrypted index"<<endl;
    cout<<"2. Keyword search: "<<endl;
    cout<<"3. Update files"<<endl;
    cout<<"4. Save current state and Exit"<<endl<<endl;;
    cout<<"---------------"<<endl;
}
