#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <new>

enum { SK_MALLOC_THROW = 1, SK_MALLOC_TEMP = 2 };
static void *sk_malloc_flags(size_t size, int) {
    void *ptr = std::malloc(size);
    if (!ptr) throw std::bad_alloc();
    return ptr;
}

template <typename T, size_t kCount>
class SkAutoSTMalloc {
    alignas(T) unsigned char storage_[sizeof(T) * kCount];
    T *fTStorage = reinterpret_cast<T *>(storage_);
    T *fPtr = nullptr;
public:
SkAutoSTMalloc(size_t counter) { if (counter > kCount) { fPtr = (T*)sk_malloc_flags(counter * sizeof(T), SK_MALLOC_THROW | SK_MALLOC_TEMP); } else if (counter) { fPtr = fTStorage; } else { fPtr = nullptr; } }

    ~SkAutoSTMalloc() {
        if (fPtr && fPtr != fTStorage) std::free(fPtr);
    }
    bool has_data() const { return fPtr != nullptr; }
    bool uses_inline_storage() const { return fPtr == fTStorage; }
};

int main() {
    SkAutoSTMalloc<int, 4> zero(0);
    SkAutoSTMalloc<int, 4> small(3);
    SkAutoSTMalloc<int, 4> large(9);
    std::cout << zero.has_data() << ':' << zero.uses_inline_storage() << '\n';
    std::cout << small.has_data() << ':' << small.uses_inline_storage() << '\n';
    std::cout << large.has_data() << ':' << large.uses_inline_storage() << '\n';
    return 0;
}
