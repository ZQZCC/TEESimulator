#include <cstddef>

// The injector never demangles names. Let terminate diagnostics fall back to
// the original name without linking libc++abi's full demangler.
extern "C" __attribute__((used, visibility("hidden"))) char *
__cxa_demangle(const char *, char *, std::size_t *, int *status) {
    if (status) {
        *status = -2;
    }
    return nullptr;
}
