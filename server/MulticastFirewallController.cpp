#include <set>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstdint>

#define LOG_TAG "MulticastFirewallController"
#define LOG_NDEBUG 0

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <log/log.h>

#include "Controllers.h"
#include "MulticastFirewallController.h"
#include "NetdConstants.h"

using android::base::Join;
using android::base::StringAppendF;
using android::base::StringPrintf;

namespace android {
namespace net {

auto MulticastFirewallController::execIptablesRestore = ::execIptablesRestore;

const char* MulticastFirewallController::TABLE = "filter";

const char* MulticastFirewallController::LOCAL_INPUT = "mfw_INPUT";
const char* MulticastFirewallController::LOCAL_FORWARD = "mfw_FORWARD";
const char* MulticastFirewallController::LOCAL_OUTPUT = "mfw_OUTPUT";

const char* MulticastFirewallController::MULTICAST_RANGE_IPV4 = "224.0.0.0/4";
const char* MulticastFirewallController::MULTICAST_RANGE_IPV6 = "ff00::/8";

MulticastFirewallController::MulticastFirewallController(void) {
    mIfaceRules = {};
}

int MulticastFirewallController::setupIptablesHooks(void) {
    return flushRules();
}

int MulticastFirewallController::flushRules() {
    std::string command = Join(std::vector<std::string> {
            "*filter",
            ":mfw_INPUT -",
            ":mfw_FORWARD -",
            ":mfw_OUTPUT -",
            // Have to match on dest addr instead of using -m addrtype --dst-type MULTICAST because
            // missing kernel module for it.
            StringPrintf("-4 -A mfw_INPUT -d %s -j DROP", MULTICAST_RANGE_IPV4),
            StringPrintf("-4 -A mfw_FORWARD -d %s -j DROP", MULTICAST_RANGE_IPV4),
            StringPrintf("-4 -A mfw_OUTPUT -d %s -j DROP", MULTICAST_RANGE_IPV4),
            StringPrintf("-6 -A mfw_INPUT -d %s -j DROP", MULTICAST_RANGE_IPV6),
            StringPrintf("-6 -A mfw_FORWARD -d %s -j DROP", MULTICAST_RANGE_IPV6),
            StringPrintf("-6 -A mfw_OUTPUT -d %s -j DROP", MULTICAST_RANGE_IPV6),
            "COMMIT\n"
    }, "\n");

    return (execIptablesRestore(V4V6, command.c_str()) == 0) ? 0 : -EREMOTEIO;
}

int MulticastFirewallController::setInterfaceRules(const char* iface, bool addingInterface) {
    // Only delete rules if we actually added them, because otherwise our iptables-restore
    // processes will terminate with "no such rule" errors and cause latency penalties while we
    // spin up new ones.
    const char* op;
    if (addingInterface && mIfaceRules.find(iface) == mIfaceRules.end()) {
        op = "-I";
        mIfaceRules.insert(iface);
    } else if (!addingInterface && mIfaceRules.find(iface) != mIfaceRules.end()) {
        op = "-D";
        mIfaceRules.erase(iface);
    } else {
        return 0;
    }

    // TODO: Insert IPv4/IPv6 rules for allowing forwarding between all physical interfaces?
    std::string command = Join(std::vector<std::string> {
            "*filter",
            StringPrintf("-4 %s mfw_INPUT -d %s -i %s -j RETURN", op, MULTICAST_RANGE_IPV4, iface),
            StringPrintf("-4 %s mfw_OUTPUT -d %s -o %s -j RETURN", op, MULTICAST_RANGE_IPV4, iface),
            StringPrintf("-6 %s mfw_INPUT -d %s -i %s -j RETURN", op, MULTICAST_RANGE_IPV6, iface),
            StringPrintf("-6 %s mfw_OUTPUT -d %s -o %s -j RETURN", op, MULTICAST_RANGE_IPV6, iface),
            "COMMIT\n"
    }, "\n");
    return (execIptablesRestore(V4V6, command) == 0) ? 0 : -EREMOTEIO;
}

}  // namespace net
}  // namespace android
