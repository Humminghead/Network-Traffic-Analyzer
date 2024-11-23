#include <gtest/gtest.h>
#include <gtest/internal/gtest-internal.h>

class CaptureModuleTest : public ::testing::Test {
public:
    CaptureModuleTest() {}
protected:
    virtual void SetUp() {}
    virtual void TearDown() {}
    static void SetUpTestSuite() {}
    static void TearDownTestSuite() {}
};

TEST_F(CaptureModuleTest, handle_eth_nullptr_test) {
    ASSERT_FALSE(false);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}
