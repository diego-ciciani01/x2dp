CUSTOM_CLANG=~/llvm-project/build/bin/clang
MULTIARCH_INC="/usr/include/$(uname -m)-linux-gnu"
CC = gcc
OBJC = bench_loader.c
TARGET = bench_loader.o

all : $(TARGET)
$(TARGET) : $(OBJC)
	$(CUSTOM_CLANG) -target bpf -g -O2 -I $(MULTIARCH_INC) -c $< -o $@

baseline_empty:
	 $(CUSTOM_CLANG) -target bpf -g -O2 -I $(MULTIARCH_INC) -c $@.bpf.c -o $@.bpf.o  
call_only:
	 $(CUSTOM_CLANG) -target bpf -g -O2 -I $(MULTIARCH_INC) -c $@.bpf.c -o $@.bpf.o  
fpu_napi_simd:
	 $(CUSTOM_CLANG) -target bpf -g -O2 -I $(MULTIARCH_INC) -c $@.bpf.c -o $@.bpf.o  
baseline_fpu_napi_simd:
	 $(CUSTOM_CLANG) -target bpf -g -O2 -I $(MULTIARCH_INC) -c $@.bpf.c -o $@.bpf.o  



bench_loader:
	$(CC) -O2 $@.c -o $@ -I ~/bpf-dev/linux/tools/lib -L ~/bpf-dev/linux/tools/lib/bpf -lbpf -left -lz



clean:
	rm -f *.o 

.PHONY: all clean
