#include "kernel_layout.h"
#include "compiled-layout.h"
#include <cstdio>
#include <fstream>
#include <iterator>
#include <stdexcept>
int main(int argc,char** argv) {
    if(argc!=2) return 2;
    std::ifstream input(argv[1],std::ios::binary);
    if(!input) return 2;
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)),std::istreambuf_iterator<char>());
    try {maplesu::module_policy::verify_kernel_layout(bytes,compiled_layout());}
    catch(const std::exception& e) {fprintf(stderr,"%s\n",e.what());return 1;}
    puts("PASS: compiled payload offsets, widths and allocated structures match target kernel BTF");
}
