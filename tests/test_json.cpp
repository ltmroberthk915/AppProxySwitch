#include "aps/json.hpp"
#include "testlib/appsw_test.h"

using aps::json::Value;

APS_TEST(json, parse_scalars) {
    Value v;
    std::string err;
    EXPECT_TRUE(Value::parse("null", v, &err));
    EXPECT_TRUE(v.isNull());

    EXPECT_TRUE(Value::parse("true", v, &err));
    EXPECT_TRUE(v.isBoolean());
    EXPECT_TRUE(v.asBool());

    EXPECT_TRUE(Value::parse("false", v, &err));
    EXPECT_FALSE(v.asBool());

    EXPECT_TRUE(Value::parse("42", v, &err));
    EXPECT_TRUE(v.isNumber());
    EXPECT_EQ(v.asInt(), 42);

    EXPECT_TRUE(Value::parse("-17", v, &err));
    EXPECT_EQ(v.asInt(), -17);

    EXPECT_TRUE(Value::parse("3.5", v, &err));
    EXPECT_TRUE(v.asNumber() > 3.49 && v.asNumber() < 3.51);

    EXPECT_TRUE(Value::parse("1e3", v, &err));
    EXPECT_EQ(v.asInt(), 1000);

    EXPECT_TRUE(Value::parse("\"hi\"", v, &err));
    EXPECT_STREQ(v.asString(), "hi");
}

APS_TEST(json, parse_whitespace_and_empty_containers) {
    Value v;
    std::string err;
    EXPECT_TRUE(Value::parse("  \r\n\t { } \t ", v, &err));
    EXPECT_TRUE(v.isObject());
    EXPECT_EQ(v.size(), 0u);

    EXPECT_TRUE(Value::parse("[ ]", v, &err));
    EXPECT_TRUE(v.isArray());
    EXPECT_EQ(v.size(), 0u);
}

APS_TEST(json, parse_nested) {
    Value v;
    std::string err;
    const char* doc =
        "{\"proxy\":{\"host\":\"127.0.0.1\",\"port\":7891},"
        "\"rules\":[{\"id\":\"a\",\"enabled\":true},{\"id\":\"b\",\"enabled\":false}]}";
    EXPECT_TRUE(Value::parse(doc, v, &err));
    const Value* proxy = v.find("proxy");
    EXPECT_TRUE(proxy != nullptr);
    EXPECT_STREQ(proxy->find("host")->asString(), "127.0.0.1");
    EXPECT_EQ(proxy->find("port")->asInt(), 7891);
    const Value* rules = v.find("rules");
    EXPECT_EQ(rules->size(), 2u);
    EXPECT_TRUE(rules->at(0).find("enabled")->asBool());
    EXPECT_FALSE(rules->at(1).find("enabled")->asBool());
}

APS_TEST(json, parse_string_escapes) {
    Value v;
    std::string err;
    EXPECT_TRUE(Value::parse("\"a\\\\b\\\"c\\/d\\be\\ff\\ng\\rh\\ti\"", v, &err));
    EXPECT_STREQ(v.asString(), "a\\b\"c/d\be\ff\ng\rh\ti");

    EXPECT_TRUE(Value::parse("\"\\u0041\\u00e9\\u4e2d\"", v, &err));
    // A, e-acute, CJK "中"
    EXPECT_STREQ(v.asString(), std::string("A\xC3\xA9\xE4\xB8\xAD"));

    // Surrogate pair for U+1F600.
    EXPECT_TRUE(Value::parse("\"\\uD83D\\uDE00\"", v, &err));
    EXPECT_STREQ(v.asString(), std::string("\xF0\x9F\x98\x80"));
}

APS_TEST(json, rejects_invalid) {
    struct Bad { const char* text; const char* why; };
    const Bad bad[] = {
        {"", "empty"},
        {"{", "unterminated object"},
        {"[1,]", "trailing comma"},
        {"{\"a\":}", "missing value"},
        {"{\"a\" 1}", "missing colon"},
        {"nul", "bad literal"},
        {"tru", "bad literal"},
        {"01", "leading zero"},
        {"1.", "frac missing digits"},
        {"+1", "plus sign"},
        {".5", "leading dot"},
        {"\"\\x\"", "bad escape"},
        {"\"\\u00zz\"", "bad hex"},
        {"\"unterminated", "string"},
        {"\"a\" \"b\"", "two values"},
        {"{} extra", "trailing content"},
        {"[1] [2]", "two documents"},
        {"\"line\nbreak\"", "raw newline in string"},
    };
    for (const auto& b : bad) {
        Value v;
        std::string err;
        bool ok = Value::parse(b.text, v, &err);
        EXPECT_FALSE(ok);
        if (ok) {
            std::printf("    (should have failed: %s)\n", b.why);
        }
    }
}

APS_TEST(json, rejects_lone_surrogates_and_bad_utf8) {
    Value v;
    std::string err;
    EXPECT_FALSE(Value::parse("\"\\uD83D\"", v, &err));       // lone high surrogate
    EXPECT_FALSE(Value::parse("\"\\uDC00\"", v, &err));       // lone low surrogate
    EXPECT_FALSE(Value::parse("\"\xFF\"", v, &err));          // invalid UTF-8 byte
    EXPECT_FALSE(Value::parse("\"\xC3\x28\"", v, &err));      // bad continuation
}

APS_TEST(json, dump_roundtrip) {
    Value v = Value::makeObject();
    v.set("name", std::string("app\"s"));
    v.set("port", 7891);
    v.set("ok", true);
    Value arr = Value::makeArray();
    arr.append(1);
    arr.append(std::string("two"));
    v.set("list", std::move(arr));

    std::string dumped = v.dump();
    Value back;
    std::string err;
    EXPECT_TRUE(Value::parse(dumped, back, &err));
    EXPECT_STREQ(back.find("name")->asString(), "app\"s");
    EXPECT_EQ(back.find("port")->asInt(), 7891);
    EXPECT_TRUE(back.find("ok")->asBool());
    EXPECT_EQ(back.find("list")->size(), 2u);
    EXPECT_STREQ(back.find("list")->at(1).asString(), "two");
}

APS_TEST(json, integral_dump_has_no_decimal_point) {
    Value v(7891);
    EXPECT_STREQ(v.dump(), "7891");
    Value f(1.5);
    EXPECT_TRUE(f.dump().find('.') != std::string::npos ||
                f.dump().find('e') != std::string::npos);
}

APS_TEST(json, object_set_overwrites_and_preserves_order) {
    Value v = Value::makeObject();
    v.set("a", 1);
    v.set("b", 2);
    v.set("a", 3);
    EXPECT_EQ(v.size(), 2u);
    EXPECT_EQ(v.find("a")->asInt(), 3);
    EXPECT_STREQ(v.dump(), "{\"a\":3,\"b\":2}");
}

APS_TEST(json, find_missing_returns_nullptr) {
    Value v = Value::makeObject();
    v.set("x", 1);
    EXPECT_TRUE(v.find("missing") == nullptr);
    // Non-object find is also safe.
    Value s(std::string("str"));
    EXPECT_TRUE(s.find("missing") == nullptr);
}

APS_TEST(json, erase_removes_key) {
    Value v = Value::makeObject();
    v.set("a", 1);
    v.set("b", 2);
    EXPECT_TRUE(v.erase("a"));
    EXPECT_TRUE(v.find("a") == nullptr);
    EXPECT_EQ(v.size(), 1u);
    EXPECT_STREQ(v.dump(), "{\"b\":2}");
    // Absent key: no-op, false.
    EXPECT_FALSE(v.erase("nope"));
    // Non-object erase is safe.
    Value s(std::string("str"));
    EXPECT_FALSE(s.erase("x"));
}

APS_TEST_MAIN();
