#ifndef SIMPLICITY_SIMPLICITY_ALLOC_H
#define SIMPLICITY_SIMPLICITY_ALLOC_H

#include <stdlib.h>

/* Declare Rust functions so the compiler can handle them.
 * The linker will include the functions from Rust.
 */
extern void* rust_malloc(size_t size);
extern void* rust_calloc(size_t num, size_t size);
extern void rust_free(void* ptr);

/* Allocate with malloc by default. */
#define simplicity_malloc rust_malloc

/* Allocate+zero initialize with calloc by default. */
#define simplicity_calloc rust_calloc

/* Deallocate with free by default. */
#define simplicity_free rust_free

#endif /* SIMPLICITY_SIMPLICITY_ALLOC_H */
