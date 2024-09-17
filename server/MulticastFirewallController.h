#ifndef _MULTICAST_FIREWALL_CONTROLLER_H
#define _MULTICAST_FIREWALL_CONTROLLER_H

#include <sys/types.h>
#include <set>
#include <string>
#include <vector>

#include "NetdConstants.h"

namespace android {
namespace net {

/*
 * Firewall that DROPs all multicast packets that aren't being sent/received on an explicitly
 * allowed interface. The main purpose of this firewall is to prevent users from sending/receiving
 * multicast traffic over the VPN (tun) interface of other users, as that would be a violation of
 * the requirement that VPNs are profile isolated.
 *
 * Based on upstream FirewallController.
 */
class MulticastFirewallController {
public:
  MulticastFirewallController();

  int setupIptablesHooks(void);

  /* Adds/removes iptables rules that allow this interface to be used for multicast traffic. */
  int setInterfaceRules(const char*, bool);

  static const char* TABLE;

  static const char* LOCAL_INPUT;
  static const char* LOCAL_OUTPUT;
  static const char* LOCAL_FORWARD;

protected:
  friend class MulticastFirewallControllerTest;
  static int (*execIptablesRestore)(IptablesTarget target, const std::string& commands);

private:
  std::set<std::string> mIfaceRules;
  int flushRules(void);

  static const char* MULTICAST_RANGE_IPV4;
  static const char* MULTICAST_RANGE_IPV6;
};

}  // namespace net
}  // namespace android

#endif
