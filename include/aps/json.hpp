// Minimal strict JSON (RFC 8259) parser/serializer.
//
// Deliberately dependency-free: config files and the IPC protocol only need a
// small, well-understood subset. Objects preserve insertion order. Limits:
// nesting depth 32, input size 1 MiB, strict number/escape grammar, trailing
// content rejected, UTF-8 well-formedness checked on strings.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aps::json {

class Value;
using Array = std::vector<Value>;
using Object = std::vector<std::pair<std::string, Value>>;

class Value {
public:
    enum class Type { Null, Boolean, Number, String, ArrayT, ObjectT };

    Value() = default;
    Value(std::nullptr_t) {}
    Value(bool b) : type_(Type::Boolean), bool_(b) {}
    Value(double n) : type_(Type::Number), num_(n) {}
    Value(int n) : type_(Type::Number), num_(static_cast<double>(n)) {}
    Value(int64_t n) : type_(Type::Number), num_(static_cast<double>(n)) {}
    Value(uint32_t n) : type_(Type::Number), num_(static_cast<double>(n)) {}
    Value(size_t n) : type_(Type::Number), num_(static_cast<double>(n)) {}
    Value(const char* s) : type_(Type::String), str_(s) {}
    Value(std::string s) : type_(Type::String), str_(std::move(s)) {}

    static Value makeArray() { Value v; v.type_ = Type::ArrayT; return v; }
    static Value makeObject() { Value v; v.type_ = Type::ObjectT; return v; }

    Type type() const { return type_; }
    bool isNull() const { return type_ == Type::Null; }
    bool isBoolean() const { return type_ == Type::Boolean; }
    bool isNumber() const { return type_ == Type::Number; }
    bool isString() const { return type_ == Type::String; }
    bool isArray() const { return type_ == Type::ArrayT; }
    bool isObject() const { return type_ == Type::ObjectT; }

    bool asBool(bool def = false) const { return isBoolean() ? bool_ : def; }
    double asNumber(double def = 0) const { return isNumber() ? num_ : def; }
    int64_t asInt(int64_t def = 0) const {
        return isNumber() ? static_cast<int64_t>(num_) : def;
    }
    const std::string& asString() const {
        static const std::string kEmpty;
        return isString() ? str_ : kEmpty;
    }

    // --- object access -------------------------------------------------------
    const Value* find(std::string_view key) const;
    Value& set(std::string key, Value v);   // insert/overwrite
    // Remove `key` (no-op for non-objects/absent keys). Returns true when a
    // pair was removed. Used by profile export to strip DPAPI secret fields.
    bool erase(std::string_view key);
    const Object& object() const { return obj_; }
    Object& object() { return obj_; }

    // --- array access ----------------------------------------------------------
    size_t size() const;
    const Value& at(size_t i) const;
    Value& append(Value v);
    const Array& array() const { return arr_; }
    Array& array() { return arr_; }

    // Compact serialization (no whitespace).
    std::string dump() const;

    // Strict parse of a complete document. Returns false and fills `error`
    // (position included) on any grammar violation.
    static bool parse(std::string_view text, Value& out, std::string* error);

private:
    Type type_ = Type::Null;
    bool bool_ = false;
    double num_ = 0.0;
    std::string str_;
    Array arr_;
    Object obj_;

    void dumpTo(std::string& out) const;
};

}  // namespace aps::json
