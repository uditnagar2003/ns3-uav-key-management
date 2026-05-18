/**
 * utils/uav-enum-strings.cc
 * Definitions of enum-to-string converters declared in uav-types.h.
 */

#include "uav-types.h"

namespace uav {
namespace utils {

const char* NodeRoleToString(NodeRole r) {
    switch (r) {
        case NodeRole::KDC:     return "KDC";
        case NodeRole::SKDC:    return "SKDC";
        case NodeRole::UAV:     return "UAV";
        case NodeRole::JAMMER:  return "JAMMER";
        case NodeRole::UNKNOWN: return "UNKNOWN";
    }
    return "INVALID_ROLE";
}

const char* UavStateToString(UavState s) {
    switch (s) {
        case UavState::UNREGISTERED:   return "UNREGISTERED";
        case UavState::AUTHENTICATING: return "AUTHENTICATING";
        case UavState::ACTIVE:         return "ACTIVE";
        case UavState::HANDOVER:       return "HANDOVER";
        case UavState::COMPROMISED:    return "COMPROMISED";
        case UavState::DISCONNECTED:   return "DISCONNECTED";
        case UavState::LEAVING:        return "LEAVING";
    }
    return "INVALID_STATE";
}

const char* SecurityEventTypeToString(SecurityEventType e) {
    switch (e) {
        case SecurityEventType::JOIN:              return "JOIN";
        case SecurityEventType::LEAVE:             return "LEAVE";
        case SecurityEventType::REKEY:             return "REKEY";
        case SecurityEventType::HANDOVER_START:    return "HANDOVER_START";
        case SecurityEventType::HANDOVER_COMPLETE: return "HANDOVER_COMPLETE";
        case SecurityEventType::COMPROMISE:        return "COMPROMISE";
        case SecurityEventType::JAMMER_DETECTED:   return "JAMMER_DETECTED";
        case SecurityEventType::AUTH_FAILURE:      return "AUTH_FAILURE";
        case SecurityEventType::REPLAY_DETECTED:   return "REPLAY_DETECTED";
        case SecurityEventType::HMAC_FAILURE:      return "HMAC_FAILURE";
        case SecurityEventType::TEK_ROTATION:      return "TEK_ROTATION";
    }
    return "INVALID_EVENT";
}

const char* StatusToString(Status s) {
    switch (s) {
        case Status::OK:                  return "OK";
        case Status::INVALID_ARGUMENT:    return "INVALID_ARGUMENT";
        case Status::NOT_FOUND:           return "NOT_FOUND";
        case Status::ALREADY_EXISTS:      return "ALREADY_EXISTS";
        case Status::OUT_OF_RANGE:        return "OUT_OF_RANGE";
        case Status::PERMISSION_DENIED:   return "PERMISSION_DENIED";
        case Status::UNAUTHENTICATED:     return "UNAUTHENTICATED";
        case Status::REPLAY_DETECTED:     return "REPLAY_DETECTED";
        case Status::HMAC_INVALID:        return "HMAC_INVALID";
        case Status::DECRYPT_FAILED:      return "DECRYPT_FAILED";
        case Status::SERIALIZATION_ERROR: return "SERIALIZATION_ERROR";
        case Status::INTERNAL_ERROR:      return "INTERNAL_ERROR";
    }
    return "INVALID_STATUS";
}

} // namespace utils
} // namespace uav