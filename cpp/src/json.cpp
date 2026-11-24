// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the small JSON value type: adding and setting values and the escaping of wide strings in its output.

#include <ddcore/json.hpp>

#include <cmath>
#include <cstdio>
#include <cwctype>
#include <stdexcept>

namespace dd {

namespace {
const Json& null_json() {
    static const Json value;
    return value;
}
}  // namespace

Json Json::boolean(bool v) {
    Json j;
    j.type_ = Type::Bool;
    j.bool_ = v;
    return j;
}
Json Json::number(double v) {
    Json j;
    j.type_ = Type::Number;
    j.number_ = v;
    return j;
}
Json Json::string(const std::wstring& v) {
    Json j;
    j.type_ = Type::String;
    j.string_ = v;
    return j;
}
Json Json::array() {
    Json j;
    j.type_ = Type::Array;
    return j;
}
Json Json::object() {
    Json j;
    j.type_ = Type::Object;
    return j;
}

const Json& Json::get(const std::wstring& key) const {
    if (type_ != Type::Object) return null_json();
    auto it = object_.find(key);
    return it == object_.end() ? null_json() : it->second;
}

const Json& Json::at(std::size_t index) const {
    return type_ == Type::Array && index < array_.size() ? array_[index] : null_json();
}

bool Json::has(const std::wstring& key) const { return type_ == Type::Object && object_.count(key) > 0; }

std::wstring Json::str(const std::wstring& fallback) const {
    switch (type_) {
        case Type::String: return string_;
        case Type::Bool: return bool_ ? L"True" : L"False";
        case Type::Number: {
            wchar_t buf[48];
            if (number_ == std::floor(number_) && std::fabs(number_) < 1e15) swprintf(buf, 48, L"%lld", (long long)number_);
            else swprintf(buf, 48, L"%g", number_);
            return buf;
        }
        default: return fallback;
    }
}

double Json::num(double fallback) const {
    if (type_ == Type::Number) return number_;
    if (type_ == Type::Bool) return bool_ ? 1 : 0;
    if (type_ == Type::String) {
        wchar_t* end = nullptr;
        double v = wcstod(string_.c_str(), &end);
        if (end && end != string_.c_str() && *end == 0) return v;
    }
    return fallback;
}

long long Json::integer(long long fallback) const {
    if (type_ == Type::Number) return (long long)number_;
    if (type_ == Type::Bool) return bool_ ? 1 : 0;
    if (type_ == Type::String) {
        wchar_t* end = nullptr;
        long long v = wcstoll(string_.c_str(), &end, 10);
        if (end && end != string_.c_str() && *end == 0) return v;
    }
    return fallback;
}

bool Json::flag(bool fallback) const {
    if (type_ == Type::Bool) return bool_;
    if (type_ == Type::Number) return number_ != 0;
    if (type_ == Type::String) return !string_.empty() && string_ != L"False" && string_ != L"false" && string_ != L"0";
    return fallback;
}

std::vector<Json> Json::as_list() const {
    if (type_ == Type::Null) return {};
    if (type_ == Type::Array) return array_;
    return {*this};
}

void Json::push(const Json& v) {
    if (type_ == Type::Null) type_ = Type::Array;
    array_.push_back(v);
}

void Json::set(const std::wstring& key, const Json& v) {
    if (type_ == Type::Null) type_ = Type::Object;
    object_[key] = v;
}

static void escape(const std::wstring& s, std::wstring& out) {
    out.push_back(L'"');
    for (wchar_t c : s) {
        switch (c) {
            case L'"': out += L"\\\""; break;
            case L'\\': out += L"\\\\"; break;
            case L'\n': out += L"\\n"; break;
            case L'\r': out += L"\\r"; break;
            case L'\t': out += L"\\t"; break;
            default:
                if (c < 0x20) {
                    wchar_t buf[8];
                    swprintf(buf, 8, L"\\u%04x", (unsigned)c);
                    out += buf;
                } else {
                    out.push_back(c);
                }
        }
    }
    out.push_back(L'"');
}

std::wstring Json::dump(bool pretty, int indent) const {
    std::wstring out, pad(pretty ? (indent + 1) * 2 : 0, L' '), end_pad(pretty ? indent * 2 : 0, L' ');
    const wchar_t* nl = pretty ? L"\n" : L"";
    switch (type_) {
        case Type::Null: return L"null";
        case Type::Bool: return bool_ ? L"true" : L"false";
        case Type::Number: return str();
        case Type::String: escape(string_, out); return out;
        case Type::Array: {
            if (array_.empty()) return L"[]";
            out = L"[";
            out += nl;
            for (std::size_t i = 0; i < array_.size(); ++i) {
                out += pad + array_[i].dump(pretty, indent + 1) + (i + 1 < array_.size() ? L"," : L"") + nl;
            }
            return out + end_pad + L"]";
        }
        case Type::Object: {
            if (object_.empty()) return L"{}";
            out = L"{";
            out += nl;
            std::size_t i = 0;
            for (const auto& [k, v] : object_) {
                std::wstring key;
                escape(k, key);
                out += pad + key + (pretty ? L": " : L":") + v.dump(pretty, indent + 1) + (++i < object_.size() ? L"," : L"") + nl;
            }
            return out + end_pad + L"}";
        }
    }
    return L"null";
}

namespace {

struct Parser {
    const std::wstring& s;
    std::size_t i = 0;

    [[noreturn]] void fail(const char* why) const { throw std::runtime_error(std::string("JSON: ") + why); }
    void skip() {
        while (i < s.size() && (iswspace(s[i]) || s[i] == 0xFEFF)) ++i;
    }
    bool take(wchar_t c) {
        skip();
        if (i < s.size() && s[i] == c) {
            ++i;
            return true;
        }
        return false;
    }

    std::wstring parse_string() {
        std::wstring out;
        ++i;   // opening quote
        while (i < s.size() && s[i] != L'"') {
            wchar_t c = s[i++];
            if (c != L'\\') {
                out.push_back(c);
                continue;
            }
            if (i >= s.size()) fail("bad escape");
            wchar_t e = s[i++];
            switch (e) {
                case L'n': out.push_back(L'\n'); break;
                case L'r': out.push_back(L'\r'); break;
                case L't': out.push_back(L'\t'); break;
                case L'b': out.push_back(L'\b'); break;
                case L'f': out.push_back(L'\f'); break;
                case L'u': {
                    if (i + 4 > s.size()) fail("bad \\u escape");
                    out.push_back((wchar_t)std::stoi(s.substr(i, 4), nullptr, 16));
                    i += 4;
                    break;
                }
                default: out.push_back(e);   // " \ /
            }
        }
        if (i >= s.size()) fail("unterminated string");
        ++i;
        return out;
    }

    Json value(int depth) {
        if (depth > 200) fail("too deep");
        skip();
        if (i >= s.size()) fail("unexpected end");
        wchar_t c = s[i];
        if (c == L'{') {
            ++i;
            Json obj = Json::object();
            if (take(L'}')) return obj;
            do {
                skip();
                if (i >= s.size() || s[i] != L'"') fail("object key expected");
                std::wstring key = parse_string();
                if (!take(L':')) fail("':' expected");
                obj.set(key, value(depth + 1));
            } while (take(L','));
            if (!take(L'}')) fail("'}' expected");
            return obj;
        }
        if (c == L'[') {
            ++i;
            Json arr = Json::array();
            if (take(L']')) return arr;
            do {
                arr.push(value(depth + 1));
            } while (take(L','));
            if (!take(L']')) fail("']' expected");
            return arr;
        }
        if (c == L'"') return Json::string(parse_string());
        if (s.compare(i, 4, L"true") == 0) {
            i += 4;
            return Json::boolean(true);
        }
        if (s.compare(i, 5, L"false") == 0) {
            i += 5;
            return Json::boolean(false);
        }
        if (s.compare(i, 4, L"null") == 0) {
            i += 4;
            return Json();
        }
        wchar_t* end = nullptr;
        double v = wcstod(s.c_str() + i, &end);
        if (end == s.c_str() + i) fail("unexpected character");
        i = (std::size_t)(end - s.c_str());
        return Json::number(v);
    }
};

}  // namespace

Json parse_json(const std::wstring& text) {
    Parser p{text};
    Json v = p.value(0);
    p.skip();
    if (p.i != text.size()) throw std::runtime_error("JSON: extra text after the value");
    return v;
}

bool try_parse_json(const std::wstring& text, Json& out) {
    try {
        out = parse_json(text);
        return true;
    } catch (const std::exception&) {
        out = Json();
        return false;
    }
}

}  // namespace dd
