#include <string>
#include <vector>
#include <stdio.h>

#include <gtest/gtest.h>

#include "MulticastFirewallController.h"
#include "IptablesBaseTest.h"

namespace android {
namespace net {

class MulticastFirewallControllerTest : public IptablesBaseTest {
protected:
    MulticastFirewallControllerTest() {
        MulticastFirewallController::execIptablesRestore = fakeExecIptablesRestore;
    }
    MulticastFirewallController mFw;
};

TEST_F(MulticastFirewallControllerTest, TestFirewall) {
    std::vector<std::string> baseCommands = {
            "*filter\n"
            ":mfw_INPUT -\n"
            ":mfw_FORWARD -\n"
            ":mfw_OUTPUT -\n"
            "-4 -A mfw_INPUT -d 224.0.0.0/4 -j DROP\n"
            "-4 -A mfw_FORWARD -d 224.0.0.0/4 -j DROP\n"
            "-4 -A mfw_OUTPUT -d 224.0.0.0/4 -j DROP\n"
            "-6 -A mfw_INPUT -d ff00::/8 -j DROP\n"
            "-6 -A mfw_FORWARD -d ff00::/8 -j DROP\n"
            "-6 -A mfw_OUTPUT -d ff00::/8 -j DROP\n"
            "COMMIT\n"};

    EXPECT_EQ(0, mFw.setupIptablesHooks());
    expectIptablesRestoreCommands(baseCommands);

    std::vector<std::string> addInterfaceCommands = {
            "*filter\n"
            "-4 -I mfw_INPUT -d 224.0.0.0/4 -i wlan0 -j RETURN\n"
            "-4 -I mfw_OUTPUT -d 224.0.0.0/4 -o wlan0 -j RETURN\n"
            "-6 -I mfw_INPUT -d ff00::/8 -i wlan0 -j RETURN\n"
            "-6 -I mfw_OUTPUT -d ff00::/8 -o wlan0 -j RETURN\n"
            "COMMIT\n"
    };

    EXPECT_EQ(0, mFw.setInterfaceRules("wlan0", true));
    expectIptablesRestoreCommands(addInterfaceCommands);

    std::vector<std::string> noCommands = {};
    EXPECT_EQ(0, mFw.setInterfaceRules("wlan0", true));
    expectIptablesRestoreCommands(noCommands);

    std::vector<std::string> removeInterfaceCommands = {
            "*filter\n"
            "-4 -D mfw_INPUT -d 224.0.0.0/4 -i wlan0 -j RETURN\n"
            "-4 -D mfw_OUTPUT -d 224.0.0.0/4 -o wlan0 -j RETURN\n"
            "-6 -D mfw_INPUT -d ff00::/8 -i wlan0 -j RETURN\n"
            "-6 -D mfw_OUTPUT -d ff00::/8 -o wlan0 -j RETURN\n"
            "COMMIT\n"
    };

    EXPECT_EQ(0, mFw.setInterfaceRules("wlan0", false));
    expectIptablesRestoreCommands(removeInterfaceCommands);

    EXPECT_EQ(0, mFw.setInterfaceRules("wlan0", false));
    expectIptablesRestoreCommands(noCommands);
}

}  // namespace net
}  // namespace android
