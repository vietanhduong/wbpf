package syms

/*
#include <stdlib.h>

static size_t get_malloc_addr__(){ return (size_t)malloc; }
*/
import "C"

func getMallocAddr() uint64 {
	return uint64(C.get_malloc_addr__())
}
