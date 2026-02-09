
#include <errno.h>
#include <cstring>
#include <format>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

/*
std::string escape_hex(const std::string &&in) {
  std::string output;
  auto remaining = in.size();
  int lc = 0;
  for (char c : in) {
    remaining--;
    output += std::format("{:02x} ", c);
    if (++lc == 8 && remaining) {
      lc = 0;
      output += '\n';
    }
  }

  return output;
}
*/

void dump(std::string &line16) {
  std::string hex_part, ascii_part;
  for(int i=0;i<16;i++) {
    if (line16.size() > i) {
      char cur = line16[i];
      hex_part += std::format("{:02x} ", cur);
      if ( cur >= ' ' && cur <= '~' ) {
        ascii_part += cur;
      } else {
        ascii_part += '.';
      }
      if (i == 7) {
        hex_part += "- ";
        ascii_part += " - ";
      }
    } else {
      hex_part += "   ";
      if (i == 7) {
        hex_part += "  ";
      }
    }
  }
  std::cout << hex_part << "    " << ascii_part << std::endl;
}

std::string line;

void dump(char c) {
  line += c;

  if (line.size() == 16) {
    dump(line);
    line.clear();
  }
}


void display_errno(const char *s) {
  std::cout << s << " (errno: " << errno << " - " << strerror(errno) << ")" << std::endl;
}

class Socket {
  int fd = -1;   // Socket handle

public:
  Socket() {};
  Socket(int fd) : fd(fd) {};

  ~Socket() {
    close();
  }


  void close() {
    if (-1 == fd) {
      ::close(fd);
    }

    fd = -1;
  }

  bool listen(unsigned port) {
    if (-1 != fd) {
      close();
    }

    // TODO: set SO_REUSEADDR so address can be reused imidiately
    fd = socket(AF_INET, SOCK_STREAM, 0);

    if (-1 == fd) {
      display_errno("Unable to create socket");
      return false;
    }

    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = INADDR_ANY;

    if(-1 == bind(fd, (struct sockaddr*)&sa, sizeof(sa))) {
      display_errno("Unable to bind socket");
      close();
      return false;
    }

    if(-1 == ::listen(fd, 1)) {
      display_errno("Unable to listen");
      close();
      return false;
    }

    std::cout << "Socket is listening" << std::endl;
    return true;
  }

  int accept() {
    int ns = ::accept(fd, nullptr, nullptr);
    if (-1 == ns) {
      display_errno("Unable to accept");
      close();
    } else {
      std::cout << "Connection established!" << std::endl;
    }

    return ns;
  }

  void read(bool loop = false) {
    bool hexmode = false;
    do {
      char c;

      auto s = recv(fd, &c, 1, 0);

      if (1 != s) {
        dump(line);
        display_errno("Couln't read");
        break;
      }

      if (!hexmode && (c == '\n' || c == '\r' || (c >= ' ' && c <= '~'))) {
        std::cout << c << std::flush;
      } else {
        if (!hexmode) {
          std::cout << "\n";
          hexmode = true;
        }
        dump(c);
      }
      //std::cout << c << std::flush;

    } while(loop);

  }


};


int main(int argc, char *argv[]) {
  std::cout << "socket_read v 0.1\n";
  if (argc != 2) {
    std::cout << "Usage " << argv[0] << " [port]" << std::endl;
    return -1;
  }

  int port_number = 0;
  try {
    std::string in_string(argv[1]);
    port_number = std::stoi(in_string);
    if (port_number < 0 || port_number > 0xFFFF) throw "Not in range";
  } catch (...) {
    std::cout << "'" << argv[1] << "' is not a valid port number" << std::endl;
    return -2;
  }

  Socket socket;

  if (socket.listen(port_number)) {
    while(true) {
      Socket client(socket.accept());
      std::cout << "------[[ TCP TRANSMISSION BEGIN ]]------" << std::endl;
      line.clear();
      client.read(true);
      std::cout << "------[[  TCP TRANSMISSION END  ]]------" << std::endl;
    }
  }

  return 0;
}
