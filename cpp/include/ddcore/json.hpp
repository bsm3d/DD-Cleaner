// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares a small JSON value type, enough for the output of PowerShell and for the files the program writes.

#pragma once

#include <map>
#include <string>
#include <vector>

namespace dd {

class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Json() = default;
    static Json boolean(bool v);
    static Json number(double v);
    static Json string(const std::wstring& v);
    static Json array();
    static Json object();

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }
    bool is_object() const { return type_ == Type::Object; }
    bool is_array() const { return type_ == Type::Array; }
    bool is_string() const { return type_ == Type::String; }
    bool is_number() const { return type_ == Type::Number; }
    bool is_bool() const { return type_ == Type::Bool; }

    // Missing keys and wrong types give neutral values, like dict.get() on PowerShell output.
    const Json& get(const std::wstring& key) const;       // null Json when absent
    const Json& at(std::size_t index) const;              // null Json when out of range
    bool has(const std::wstring& key) const;
    std::wstring str(const std::wstring& fallback = L"") const;   // numbers and bools are written out
    double num(double fallback = 0) const;
    long long integer(long long fallback = 0) const;
    bool flag(bool fallback = false) const;
    // PowerShell JSON: null -> [], a single object -> [object], an array -> itself.
    std::vector<Json> as_list() const;
    const std::vector<Json>& items() const { return array_; }
    const std::map<std::wstring, Json>& members() const { return object_; }
    std::size_t size() const { return type_ == Type::Array ? array_.size() : type_ == Type::Object ? object_.size() : 0; }

    void push(const Json& v);
    void set(const std::wstring& key, const Json& v);
    std::wstring dump(bool pretty = false, int indent = 0) const;

private:
    Type type_ = Type::Null;
    bool bool_ = false;
    double number_ = 0;
    std::wstring string_;
    std::vector<Json> array_;
    std::map<std::wstring, Json> object_;
};

// Throws std::runtime_error on malformed input. A UTF-8 BOM and surrounding whitespace are accepted.
Json parse_json(const std::wstring& text);
// False (and a null result) instead of throwing.
bool try_parse_json(const std::wstring& text, Json& out);

}  // namespace dd
