#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

int main(){
  int fd, rb, rs;

  char buf[128];
  struct timeval tv;

  fd_set readfds;
  fd = open("select_file",O_RDONLY);
  if(fd < 0){
        perror("file open error ");
        exit(0);
  }
  memset(buf, 0x00, 128);
  
  FD_ZERO(&readfds);
  while(1){
        FD_SET(fd,&readfds);

        rs = select(fd+1, &readfds, NULL, NULL, NULL);

        if(rs == -1){
                perror("select error ");
                exit(0);
        }

        if(FD_ISSET(fd, &readfds)){
                while(( rb = read(fd, buf, 128)) > 0)
                        printf("%s",buf);
        }

        memset(buf, 0x00, 128);
        sleep(0);
  }
}