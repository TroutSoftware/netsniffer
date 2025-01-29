#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <fcntl.h>
#include <unistd.h>
#include <exception>

using namespace std::chrono_literals;

int open_pipe(std::string pipe_name) {
  std::cout << "\nOpening pipe for input: " << pipe_name << " ..." << std::flush;  
std::cout << "1..." << std::flush;
  int input_pipe = open(pipe_name.c_str(), O_RDONLY | O_NONBLOCK);
std::cout << "2..." << std::flush;
  if (input_pipe < 0) {
    std::cout << "Unable to open input pipe: " << pipe_name << '\n';
    exit( -1);
  }

  std::cout << "OK\nPipe is ready\n\n" << std::endl;

  return input_pipe;
}

bool done = true;

void read_cin(std::string &input) {
  std::cout << "\nWaiting for command\n"
               "\tq = Quit\n"
               "\tc = Close pipe\n"
               "\to = (Re-)open pipe\n" 
               "\tt = Toggle reading from pipe\n" 
               "\tm = Toggle mute output\n" << std::endl;
  std::cin >> input;  
  done = true;
}



int main(int argc, char *argv[]) {
  std::cout << "pipe_read v 0.0\n";
  if (argc != 2) {
    std::cout << "Usage " << argv[0] << " input_pipe\n";
    return -1;
  }

  std::string pipe_name = argv[1];

  int input_pipe = open_pipe(pipe_name);

  std::string ins;
  std::string os;

  std::thread reader;

  bool read_enabled = true;
  bool mute = false;
  size_t read_sum = 0;
    
  do {

      if (done) {

        if (reader.joinable()) {
          reader.join();
        }

        std::string ui = ins;
              
        if (ui.size()>0) {
          if (ui == "q") break;
            else if (ui == "c") {
              close(input_pipe);
              input_pipe = -1;
              std::cout << "\nPipe closed" << std::endl;
          } else if (ui == "o") {
            if (input_pipe < 0) {
              close(input_pipe);              
            }
            input_pipe = open_pipe(pipe_name);
          } else if (ui == "t") {
            read_enabled = !read_enabled;
            if(read_enabled)
              std::cout << "\nReading enabled" << std::endl;
            else
              std::cout << "\nReading suspended" << std::endl;
          } else if (ui == "m") {
            mute = !mute;
            if(mute)
              std::cout << "\nmuting" << std::endl;
            else
              std::cout << "\nunmuting" << std::endl;            
          } else {
            std::cout << "\nnot a valid command" << std::endl;
          }
        }
        done = false;
        std::thread tmp(read_cin, std::ref(ins));
        std::swap(reader, tmp);
      }

      if (input_pipe >= 0 && read_enabled) {
        char c;
        auto sz = read(input_pipe, &c, 1);

        if (sz <= 0) {
          std::this_thread::sleep_for(200ms);
        } else {
          read_sum++;
          if (!mute) {
            if (c == '\n') {
              std::cout << "\\n" << std::endl;
            } else if (c == '\r') {
              std::cout << "\\r" << std::flush;
            } else {      
              std::cout << (char)c << std::flush;
            }
          } else {
            std::cout << "\rReceived " << read_sum << " bytes" << std::flush;
          }
        }
      } else {
        std::this_thread::sleep_for(200ms);
      }
  } while (true);
   
  return 0;
}
