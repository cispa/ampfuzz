#define _GNU_SOURCE
#include <dlfcn.h>

#define FIONBIO               0x5421

int (*real_ioctl)(int fildes, unsigned long request, char* arg);

__attribute__((constructor))
void init(){
  real_ioctl = dlsym(RTLD_NEXT, "ioctl");
}

int ioctl(int fildes, unsigned long request, char* arg){
  if(fildes <= 2 && request == FIONBIO){
    return 0;
  }
  return real_ioctl(fildes, request, arg);
}
