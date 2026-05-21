#include <stdlib.h>

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
void bz_internal_error(int errcode) {
    (void)errcode;
    abort();
}
