
#include <errno.h>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

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

  void listen(unsigned port) {
    if (-1 != fd) {
      close();
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);

    if (-1 == fd) {
      display_errno("Unable to create socket");
      return;
    }

    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = INADDR_ANY;

    if(-1 == bind(fd, (struct sockaddr*)&sa, sizeof(sa))) {
      display_errno("Unable to bind socket");
      close();
      return;
    }

    if(-1 == ::listen(fd, 1)) {
      display_errno("Unable to listen");
      close();
      return;
    }

    std::cout << "Socket is listening" << std::endl;
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
    do {
      char c;

      auto s = recv(fd, &c, 1, 0);

      if (1 != s) {
        display_errno("Couln't read");
        break;
      }

      std::cout << c << std::flush;

    } while(loop);

  }


};


int main(int argc, char *argv[]) {
  std::cout << "socket_read v 0.0\n";
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

  socket.listen(port_number);

  Socket client(socket.accept());

  client.read(true);

  return 0;
}
