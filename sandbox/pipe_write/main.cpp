#include <fstream>
#include <iostream>
#include <string>
#include <csignal>
#include <atomic>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

/*
std::ofstream open_pipe(std::string pipe_name) {
  std::cout << "\nOpening pipe for output: " << pipe_name << " ..." << std::flush;
  std::ofstream output_pipe;
  std::ios_base::openmode pipe_mode = std::ios_base::out | std::ios_base::binary;
std::cout << "1..." << std::flush;
  output_pipe.open(pipe_name, pipe_mode);
std::cout << "2..." << std::flush;
  if (!output_pipe.good() || !output_pipe.is_open()) {
    std::cout << "Unable to open output pipe: " << pipe_name << '\n';
    exit( -1);
  }

  std::cout << "OK\nPipe is ready\n\n" << std::endl;

  return output_pipe;
}
*/
int open_pipe(std::string pipe_name, bool non_block = true, bool rw_mode = false) {
  std::cout << "\nOpening pipe for " << (non_block?"non-blocking":"blocking") << " " << (rw_mode?"O_RDWR":"O_WRONLY") << " output: " << pipe_name << " ..." << std::flush;  
std::cout << "1..." << std::flush;
  int output_pipe = open(pipe_name.c_str(), (rw_mode?O_RDWR:O_WRONLY) | (non_block?O_NONBLOCK:0));
std::cout << "2..." << std::flush;
  if (output_pipe < 0) {
    std::cout << "Unable to open output pipe: " << pipe_name << '\n';
    std::cout << "errno = " << strerror(errno) << std::endl;
    return -1;
  }

  std::cout << "OK\nPipe is ready (" << output_pipe << ")\n\n" << std::endl;

  return output_pipe;
}

volatile std::atomic_bool sigpipe = false;

void pipe_signal_handler(int) {
  sigpipe = true;
}

int main(int argc, char *argv[]) {
  std::cout << "pipe_write v 0.0\n";
  if (argc != 2) {
    std::cout << "Usage " << argv[0] << " output_pipe\n";
    return -1;
  }

  std::signal(SIGPIPE, pipe_signal_handler); 

  std::string pipe_name = argv[1];

  bool append_newline = true;

  //std::ofstream output_pipe = open_pipe(pipe_name);
  int output_pipe = open_pipe(pipe_name);

  std::string ins;

  do {
    std::cout << "Type text and press enter to send, press Enter on blank line for menu" << std::endl;

    std::getline(std::cin, ins);    

    std::cout << "Read: " << ins << std::endl;
send_ins:
    if (ins != "") {
      if (output_pipe >= 0) {
        if(append_newline) {
          std::cout << "Sending >" << ins << "< (with appended newline)" << std::endl;
          ins += '\n';
        } else {
          std::cout << "Sending >" << ins << "<" << std::endl;
        }

        size_t size_to_send = ins.size();
        auto bw = write(output_pipe, ins.c_str(), size_to_send);

        if (sigpipe) {
          std::cout << "SIGPIPE!!!" << std::endl;
          sigpipe = false;
        }

        if (bw == size_to_send) {
          std::cout << "Sent " << bw << " bytes on pipe" << std::endl;
        } else if (bw >= 0) {
          std::cout << "Send buffer full, sent " << bw << " bytes on pipe" << std::endl;
        } else {
          std::cout << "Error sending on (" << output_pipe << ") - errno = " << strerror(errno) << std::endl;
        }
        
      } else {
        std::cout << "Pipe closed can't send" << std::endl;
      }

      /*
      output_pipe << ins << std::endl << std::flush;      
      if (sigpipe) {
        std::cout << "SIGPIPE!!!" << std::endl;
        sigpipe = false;
      } else if (output_pipe.good() && output_pipe.is_open()) {
        std::cout << "sent >" << ins << "< on pipe" << std::endl;
      } else {
        std::cout << std::boolalpha << "data not sent - good=" << output_pipe.good() << " open=" << output_pipe.is_open() << " fail=" << output_pipe.fail() << " bad=" << output_pipe.bad() << " eof=" << output_pipe.eof() <<  std::endl;
      }
      */
    } else {
      std::cout << "Menu, enter command followed by enter:\n\tq = Quit" << std::endl;
      std::cout << "\ta = Toggle appending newlines to input" << std::endl;
      std::cout << "\tb = (Re)open pipe in blocking mode" << std::endl;
      std::cout << "\tbrw = (Re)open pipe in blocking rw mode" << std::endl;               
      std::cout << "\tc = Close pipe" << std::endl;
      std::cout << "\tf = Send to pipe until error" << std::endl;
      std::cout << "\tk = Send 1K of data (1024 bytes)" << std::endl;
      std::cout << "\tn = Send newline (\\n)" << std::endl;
      std::cout << "\to = (Re)open pipe in non-blocking mode" << std::endl;
      std::cout << "\torw = (Re)open pipe in non-blocking rw mode" << std::endl;               
      std::cout << "\tr = Send carriage return (\\r)" << std::endl;
      
      std::cout << "\tt = Toggle blocking mode" << std::endl;      
      std::cout << "\tx = Continue (exit menu)" << std::endl;

      std::getline(std::cin, ins);    

      if (ins == "q") break;
      else if (ins == "x") continue;
      //else if (ins == "r") output_pipe << "\r" << std::flush;
      //else if (ins == "n") output_pipe << "\n" << std::flush;
      else if (ins == "r") {
        ins = "\r";
        goto send_ins;
      }
      else if (ins == "n") {
        ins = "\n";
        goto send_ins;
      }
      else if (ins == "o") {
        if(output_pipe >= 0) close(output_pipe);
        output_pipe = open_pipe(pipe_name);
      }
      else if (ins == "b") {
        if(output_pipe >= 0) close(output_pipe);
        output_pipe = open_pipe(pipe_name, false);
      }
      else if (ins == "brw") {
        if(output_pipe >= 0) close(output_pipe);
        output_pipe = open_pipe(pipe_name, false, true);
      }
      else if (ins == "orw") {
        if(output_pipe >= 0) close(output_pipe);
        output_pipe = open_pipe(pipe_name, true, true);
      }
      
      else if (ins == "c") {
        if(output_pipe >= 0) close(output_pipe);
        output_pipe = -1;
      }
      else if (ins == "t") {
        if ( output_pipe >= 0) {
          int fstatus = fcntl(output_pipe, F_GETFL);
          fstatus ^= O_NONBLOCK;
          std::cout << "Setting file to " << ((fstatus & O_NONBLOCK)?"non-":"") << "blocking mode" << std::endl;
          fcntl(output_pipe, F_SETFL, fstatus);
        } else {
          std::cout << "No file open to toggle blocking mode on" << std::endl;
        }
      }
      else if (ins == "k") {
        size_t i;
        for (i=0;i<1024;i++) {
          const char* c = ".";
          auto bw = write(output_pipe, c, 1);

          if (sigpipe) {
            std::cout << "SIGPIPE!!!" << std::endl;
            sigpipe = false;
          }

          if (bw < 0) {
            std::cout << "Error sending on (" << output_pipe << ") - errno = " << strerror(errno) << std::endl;            
            break;
          }
        }
        std::cout << "Sent " << i << " bytes on pipe" << std::endl;
      }
      else if (ins == "f") {
        size_t i = 0;
        while (true) {
          const char* c = ".";
          auto bw = write(output_pipe, c, 1);

          if (sigpipe) {
            std::cout << "SIGPIPE!!!" << std::endl;
            sigpipe = false;
          }

          if (bw < 0) {
            std::cout << "Error sending on (" << output_pipe << ") - errno = " << strerror(errno) << std::endl;
            break;
          }
          i++;
        }
        std::cout << "Sent " << i << " bytes on pipe" << std::endl;
      }
      else if (ins == "a") {
        append_newline = !append_newline;
        if (append_newline) std::cout << "Will now append newlines to input" << std::endl;
        else std::cout << "Stopping appending newlines to input" << std::endl;
      }
      else {
        std::cout << "not a valid command" << std::endl;
      }
      
    }

  } while (true);
    
  return 0;
}
