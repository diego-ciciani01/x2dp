USTOM_CLANG=~/llvm-project/build/bin/clang
MULTIARCH_INC="/usr/include/$(uname -m)-linux-gnu"
CC = gcc


kfunc_call_only:
	         $(CUSTOM_CLANG) -target bpf -g -O2 -I $(MULTIARCH_INC) -c $@.bpf.c -o $@.bpf.o



