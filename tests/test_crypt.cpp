#include "aps/dpapi.hpp"
#include "aps/string_util.hpp"
#include "testlib/appsw_test.h"

#include <windows.h>

using namespace aps;

APS_TEST(crypt, base64_roundtrip) {
    for (const std::string& s : {std::string(""), std::string("f"),
                                 std::string("fo"), std::string("foo"),
                                 std::string("foob"), std::string("fooba"),
                                 std::string("foobar"),
                                 std::string("\x00\x01\xFF\x7E", 4)}) {
        std::string enc = base64Encode(reinterpret_cast<const uint8_t*>(s.data()), s.size());
        std::vector<uint8_t> dec;
        EXPECT_TRUE(base64Decode(enc, dec));
        std::string back(dec.begin(), dec.end());
        EXPECT_EQ(back, s);
    }
    EXPECT_STREQ(base64Encode(reinterpret_cast<const uint8_t*>("foobar"), 6), "Zm9vYmFy");
    EXPECT_STREQ(base64Encode(reinterpret_cast<const uint8_t*>("foob"), 4), "Zm9vYg==");
}

APS_TEST(crypt, base64_rejects_bad_input) {
    std::vector<uint8_t> out;
    EXPECT_FALSE(base64Decode("A", out));       // bad length
    EXPECT_FALSE(base64Decode("AAAAA", out));   // bad length
    EXPECT_FALSE(base64Decode("A===", out));    // bad padding
    EXPECT_FALSE(base64Decode("A?B/", out));    // bad char
    EXPECT_FALSE(base64Decode("AA=A", out));    // '=' in middle
}

APS_TEST(crypt, dpapi_roundtrip) {
    const std::string secret = "p@ssw0rd-密码-\x01\x7F";
    std::string enc = crypto::protectToBase64(secret);
    EXPECT_FALSE(enc.empty());
    bool ok = false;
    std::string back = crypto::unprotectFromBase64(enc, &ok);
    EXPECT_TRUE(ok);
    EXPECT_EQ(back, secret);
}

APS_TEST(crypt, dpapi_empty_is_empty) {
    std::string enc = crypto::protectToBase64("");
    EXPECT_TRUE(enc.empty());
    bool ok = false;
    std::string back = crypto::unprotectFromBase64("", &ok);
    EXPECT_TRUE(ok);
    EXPECT_TRUE(back.empty());
}

APS_TEST(crypt, dpapi_garbage_fails) {
    bool ok = true;
    std::string back = crypto::unprotectFromBase64("AAAAnotvalidbase64data!!", &ok);
    EXPECT_FALSE(ok);
    EXPECT_TRUE(back.empty());
}

APS_TEST_MAIN();
