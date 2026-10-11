#include "aps/json.hpp"

#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace aps::json {

namespace {

constexpr size_t kMaxDepth = 32;
constexpr size_t kMaxInput = 1u << 20;  // 1 MiB

struct Parser {
    std::string_view in;
    size_t pos = 0;
    std::string error;
    size_t depth = 0;

    bool fail(const std::string& msg) {
        if (error.empty()) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), " at offset %zu", pos);
            error = msg + buf;
        }
        return false;
    }

    void skipWs() {
        while (pos < in.size()) {
            char c = in[pos];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++pos;
            else break;
        }
    }

    bool parseValue(Value& out) {
        if (++depth > kMaxDepth) return fail("nesting too deep");
        skipWs();
        if (pos >= in.size()) return fail("unexpected end of input");
        bool ok = false;
        switch (in[pos]) {
            case '{': ok = parseObject(out); break;
            case '[': ok = parseArray(out); break;
            case '"': {
                std::string s;
                ok = parseString(s);
                if (ok) out = Value(std::move(s));
                break;
            }
            case 't': ok = parseLit("true"); if (ok) out = Value(true); break;
            case 'f': ok = parseLit("false"); if (ok) out = Value(false); break;
            case 'n': ok = parseLit("null"); if (ok) out = Value(nullptr); break;
            default: ok = parseNumber(out); break;
        }
        --depth;
        return ok;
    }

    bool parseLit(const char* lit) {
        size_t n = std::strlen(lit);
        if (in.compare(pos, n, lit) == 0) {
            pos += n;
            return true;
        }
        return fail(std::string("invalid literal, expected '") + lit + "'");
    }

    bool parseObject(Value& out) {
        out = Value::makeObject();
        ++pos;  // '{'
        skipWs();
        if (pos < in.size() && in[pos] == '}') { ++pos; return true; }
        while (true) {
            skipWs();
            if (pos >= in.size() || in[pos] != '"') return fail("expected object key string");
            std::string key;
            if (!parseString(key)) return false;
            skipWs();
            if (pos >= in.size() || in[pos] != ':') return fail("expected ':' after object key");
            ++pos;
            Value v;
            if (!parseValue(v)) return false;
            out.set(std::move(key), std::move(v));
            skipWs();
            if (pos >= in.size()) return fail("unterminated object");
            if (in[pos] == ',') { ++pos; continue; }
            if (in[pos] == '}') { ++pos; return true; }
            return fail("expected ',' or '}' in object");
        }
    }

    bool parseArray(Value& out) {
        out = Value::makeArray();
        ++pos;  // '['
        skipWs();
        if (pos < in.size() && in[pos] == ']') { ++pos; return true; }
        while (true) {
            Value v;
            if (!parseValue(v)) return false;
            out.append(std::move(v));
            skipWs();
            if (pos >= in.size()) return fail("unterminated array");
            if (in[pos] == ',') { ++pos; continue; }
            if (in[pos] == ']') { ++pos; return true; }
            return fail("expected ',' or ']' in array");
        }
    }

    bool parseString(std::string& out) {
        ++pos;  // opening quote
        out.clear();
        while (true) {
            if (pos >= in.size()) return fail("unterminated string");
            unsigned char c = static_cast<unsigned char>(in[pos]);
            if (c == '"') { ++pos; return true; }
            if (c < 0x20) return fail("raw control character in string");
            if (c == '\\') {
                ++pos;
                if (pos >= in.size()) return fail("unterminated escape");
                char e = in[pos++];
                switch (e) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        uint32_t cp;
                        if (!parseHex4(cp)) return false;
                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            // high surrogate must be followed by \uDC00-\uDFFF
                            if (pos + 1 < in.size() && in[pos] == '\\' && in[pos + 1] == 'u') {
                                pos += 2;
                                uint32_t lo;
                                if (!parseHex4(lo)) return false;
                                if (lo < 0xDC00 || lo > 0xDFFF)
                                    return fail("invalid low surrogate");
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            } else {
                                return fail("lone high surrogate");
                            }
                        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                            return fail("lone low surrogate");
                        }
                        appendUtf8(out, cp);
                        break;
                    }
                    default: return fail("invalid escape character");
                }
                continue;
            }
            // Copy UTF-8 bytes, validating well-formedness.
            size_t start = pos;
            if (!skipUtf8Sequence()) return fail("invalid UTF-8 sequence in string");
            out.append(in.data() + start, pos - start);
        }
    }

    bool parseHex4(uint32_t& out) {
        if (pos + 4 > in.size()) return fail("truncated \\u escape");
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            char c = in[pos + i];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') v |= static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= static_cast<uint32_t>(c - 'A' + 10);
            else return fail("invalid hex digit in \\u escape");
        }
        pos += 4;
        out = v;
        return true;
    }

    bool skipUtf8Sequence() {
        unsigned char c = static_cast<unsigned char>(in[pos]);
        size_t n;
        if (c < 0x80) { ++pos; return true; }
        else if ((c & 0xE0) == 0xC0) n = 2;
        else if ((c & 0xF0) == 0xE0) n = 3;
        else if ((c & 0xF8) == 0xF0) n = 4;
        else return false;
        if (pos + n > in.size()) return false;
        for (size_t i = 1; i < n; ++i) {
            if ((static_cast<unsigned char>(in[pos + i]) & 0xC0) != 0x80) return false;
        }
        // Reject overlong encodings and out-of-range code points (RFC 3629).
        uint32_t cp = 0;
        for (size_t i = 0; i < n; ++i) {
            cp = (cp << 8) | static_cast<unsigned char>(in[pos + i]);
        }
        if (n == 2 && cp < 0xC280u) return false;
        if (n == 3 && (cp < 0xE0A080u || (cp >= 0xEDA080u && cp <= 0xEDBFBFu))) {
            return false;  // U+0800 min / surrogate range
        }
        if (n == 4 && (cp < 0xF0908080u || cp > 0xF48FBFBFu)) return false;
        pos += n;
        return true;
    }

    static void appendUtf8(std::string& out, uint32_t cp) {
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    bool parseNumber(Value& out) {
        size_t start = pos;
        if (pos < in.size() && in[pos] == '-') ++pos;
        if (pos >= in.size()) return fail("invalid number");
        if (in[pos] == '0') {
            ++pos;
        } else if (in[pos] >= '1' && in[pos] <= '9') {
            while (pos < in.size() && in[pos] >= '0' && in[pos] <= '9') ++pos;
        } else {
            return fail("invalid number");
        }
        bool isInt = true;
        if (pos < in.size() && in[pos] == '.') {
            isInt = false;
            ++pos;
            if (pos >= in.size() || in[pos] < '0' || in[pos] > '9')
                return fail("digit expected after '.'");
            while (pos < in.size() && in[pos] >= '0' && in[pos] <= '9') ++pos;
        }
        if (pos < in.size() && (in[pos] == 'e' || in[pos] == 'E')) {
            isInt = false;
            ++pos;
            if (pos < in.size() && (in[pos] == '+' || in[pos] == '-')) ++pos;
            if (pos >= in.size() || in[pos] < '0' || in[pos] > '9')
                return fail("digit expected in exponent");
            while (pos < in.size() && in[pos] >= '0' && in[pos] <= '9') ++pos;
        }
        std::string tok(in.substr(start, pos - start));
        if (tok == "-" || tok.empty()) return fail("invalid number");
        if (isInt) {
            // Exact integer path (config values, ports, counters).
            errno = 0;
            char* end = nullptr;
            long long v = std::strtoll(tok.c_str(), &end, 10);
            if (errno == 0 && end && *end == '\0') {
                out = Value(static_cast<double>(v));
                return true;
            }
        }
        out = Value(std::strtod(tok.c_str(), nullptr));
        return true;
    }
};

void dumpString(const std::string& s, std::string& out) {
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
}

void dumpNumber(double n, std::string& out) {
    if (std::isnan(n) || std::isinf(n)) {
        out += "null";  // JSON has no NaN/Inf
        return;
    }
    // Print integral values without a decimal part (round-trips fine for the
    // magnitudes this project serializes, and keeps configs readable).
    double r = std::round(n);
    if (std::fabs(n - r) < 1e-9 && std::fabs(r) < 9.0e15) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(r));
        out += buf;
    } else {
        char buf[40];
        std::snprintf(buf, sizeof(buf), "%.17g", n);
        out += buf;
    }
}

}  // namespace

const Value* Value::find(std::string_view key) const {
    for (const auto& kv : obj_) {
        if (kv.first == key) return &kv.second;
    }
    return nullptr;
}

Value& Value::set(std::string key, Value v) {
    for (auto& kv : obj_) {
        if (kv.first == key) {
            kv.second = std::move(v);
            return kv.second;
        }
    }
    obj_.emplace_back(std::move(key), std::move(v));
    type_ = Type::ObjectT;
    return obj_.back().second;
}

bool Value::erase(std::string_view key) {
    if (type_ != Type::ObjectT) return false;
    for (auto it = obj_.begin(); it != obj_.end(); ++it) {
        if (it->first == key) {
            obj_.erase(it);
            return true;
        }
    }
    return false;
}

size_t Value::size() const {
    return type_ == Type::ArrayT ? arr_.size() : (type_ == Type::ObjectT ? obj_.size() : 0);
}

const Value& Value::at(size_t i) const {
    static const Value kNull;
    if (type_ != Type::ArrayT || i >= arr_.size()) return kNull;
    return arr_[i];
}

Value& Value::append(Value v) {
    type_ = Type::ArrayT;
    arr_.push_back(std::move(v));
    return arr_.back();
}

void Value::dumpTo(std::string& out) const {
    switch (type_) {
        case Type::Null: out += "null"; break;
        case Type::Boolean: out += bool_ ? "true" : "false"; break;
        case Type::Number: dumpNumber(num_, out); break;
        case Type::String: dumpString(str_, out); break;
        case Type::ArrayT: {
            out.push_back('[');
            for (size_t i = 0; i < arr_.size(); ++i) {
                if (i) out.push_back(',');
                arr_[i].dumpTo(out);
            }
            out.push_back(']');
            break;
        }
        case Type::ObjectT: {
            out.push_back('{');
            for (size_t i = 0; i < obj_.size(); ++i) {
                if (i) out.push_back(',');
                dumpString(obj_[i].first, out);
                out.push_back(':');
                obj_[i].second.dumpTo(out);
            }
            out.push_back('}');
            break;
        }
    }
}

std::string Value::dump() const {
    std::string out;
    out.reserve(256);
    dumpTo(out);
    return out;
}

bool Value::parse(std::string_view text, Value& out, std::string* error) {
    // Tolerate a UTF-8 BOM (e.g. configs saved by PowerShell 5.1 editors).
    if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEF &&
        static_cast<unsigned char>(text[1]) == 0xBB &&
        static_cast<unsigned char>(text[2]) == 0xBF) {
        text.remove_prefix(3);
    }
    if (text.size() > kMaxInput) {
        if (error) *error = "input exceeds 1 MiB limit";
        return false;
    }
    Parser p{text};
    if (!p.parseValue(out)) {
        if (error) *error = p.error.empty() ? "parse failed" : p.error;
        return false;
    }
    p.skipWs();
    if (p.pos != text.size()) {
        if (error) *error = "trailing content after JSON document";
        return false;
    }
    return true;
}

}  // namespace aps::json
