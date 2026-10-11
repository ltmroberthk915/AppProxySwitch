// Tiny test framework: registration macro, assertion macros, runner.
// Deliberately dependency-free so every test target compiles standalone.
#pragma once

#include <cstdio>
#include <cstdlib>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace aps::test {

struct Case {
    const char* name;
    void (*fn)();
};

inline std::vector<Case>& registry() {
    static std::vector<Case> r;
    return r;
}
inline int& assertionCount() { static int c = 0; return c; }
inline int& failureCount() { static int c = 0; return c; }

inline void registerCase(const char* name, void (*fn)()) {
    registry().push_back(Case{name, fn});
}

template <typename T>
std::string repr(const T& v) {
    std::ostringstream os;
    os << v;
    return os.str();
}
inline std::string repr(const std::string& v) { return "\"" + v + "\""; }
inline std::string repr(bool v) { return v ? "true" : "false"; }
inline std::string repr(std::nullptr_t) { return "null"; }

inline void reportFailure(const char* file, int line, const std::string& msg) {
    ++failureCount();
    std::printf("    FAIL %s:%d\n      %s\n", file, line, msg.c_str());
}

inline int runAll(const char* exeName) {
    (void)exeName;
    setvbuf(stdout, nullptr, _IONBF, 0);
    int failed = 0;
    for (const Case& c : registry()) {
        int before = failureCount();
        std::printf("[ RUN  ] %s\n", c.name);
        try {
            c.fn();
        } catch (const std::exception& e) {
            reportFailure(c.name, 0, std::string("uncaught exception: ") + e.what());
        } catch (...) {
            reportFailure(c.name, 0, "uncaught unknown exception");
        }
        if (failureCount() > before) {
            ++failed;
            std::printf("[ FAIL ] %s\n", c.name);
        } else {
            std::printf("[  OK  ] %s\n", c.name);
        }
    }
    std::printf("\n%d test(s), %d assertion(s), %d failure(s)\n",
                static_cast<int>(registry().size()), assertionCount(), failureCount());
    return failed == 0 ? 0 : 1;
}

}  // namespace aps::test

#define APS_TEST(suite, name)                                                  \
    static void suite##_##name##_impl();                                       \
    static const bool suite##_##name##_reg = [] {                              \
        ::aps::test::registerCase(#suite "." #name, &suite##_##name##_impl);    \
        return true;                                                           \
    }();                                                                       \
    static void suite##_##name##_impl()

#define APS_TEST_MAIN() int main() { return ::aps::test::runAll(nullptr); }

#define APS_EXPECT_OP(a, b, op, opname)                                        \
    do {                                                                       \
        ++::aps::test::assertionCount();                                       \
        if (!((a) op(b))) {                                                    \
            ::aps::test::reportFailure(__FILE__, __LINE__,                     \
                std::string("expected ") + #a + " " opname + " " + #b +        \
                ", got " + ::aps::test::repr(a) + " vs " +                     \
                ::aps::test::repr(b));                                         \
        }                                                                      \
    } while (0)

#define EXPECT_TRUE(x)  APS_EXPECT_OP(x, true, ==, "==")
#define EXPECT_FALSE(x) APS_EXPECT_OP(x, false, ==, "==")
#define EXPECT_EQ(a, b) APS_EXPECT_OP(a, b, ==, "==")
#define EXPECT_NE(a, b) APS_EXPECT_OP(a, b, !=, "!=")
#define EXPECT_LT(a, b) APS_EXPECT_OP(a, b, <,  "<")
#define EXPECT_LE(a, b) APS_EXPECT_OP(a, b, <=, "<=")
#define EXPECT_GT(a, b) APS_EXPECT_OP(a, b, >,  ">")
#define EXPECT_GE(a, b) APS_EXPECT_OP(a, b, >=, ">=")

#define EXPECT_STREQ(a, b)                                                     \
    do {                                                                       \
        ++::aps::test::assertionCount();                                       \
        std::string sa_ = (a), sb_ = (b);                                      \
        if (sa_ != sb_) {                                                      \
            ::aps::test::reportFailure(__FILE__, __LINE__,                     \
                std::string("strings differ:\n      left:  \"") + sa_ +        \
                "\"\n      right: \"" + sb_ + "\"");                           \
        }                                                                      \
    } while (0)
