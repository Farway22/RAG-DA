#include <iostream>

class Variant {
public:
    explicit Variant(bool referenced) : referenced_(referenced) {}
    bool isReferenced() const { return referenced_; }
private:
    bool referenced_;
};

class ArrayData {
public:
    enum Kind { kNormalKind, kGlobalsKind, kProxyKind };
    explicit ArrayData(Kind kind) : kind_(kind) {}
    Kind kind() const { return kind_; }
private:
    Kind kind_;
};

class Array {
public:
    explicit Array(const ArrayData *data) : data_(data) {}
    const ArrayData *get() const { return data_; }
private:
    const ArrayData *data_;
};

static bool couldRecur(const Variant& v, const Array& arr_ptr) { return v.isReferenced() || arr_ptr.get()->kind() == ArrayData::kGlobalsKind || arr_ptr.get()->kind() == ArrayData::kProxyKind; }

int main() {
    const ArrayData normal(ArrayData::kNormalKind);
    const ArrayData globals(ArrayData::kGlobalsKind);
    const ArrayData proxy(ArrayData::kProxyKind);
    std::cout << couldRecur(Variant(false), Array(&normal)) << '\n';
    std::cout << couldRecur(Variant(true), Array(&normal)) << '\n';
    std::cout << couldRecur(Variant(false), Array(&globals)) << '\n';
    std::cout << couldRecur(Variant(false), Array(&proxy)) << '\n';
    return 0;
}
