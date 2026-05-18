/**
 * utils/uav-json-validator.cc
 */

#include "uav-json-validator.h"
#include "uav-error.h"
#include "uav-string-utils.h"

namespace uav {
namespace json {

const char* JsonFieldTypeToString(JsonFieldType t) {
    switch (t) {
        case JsonFieldType::STRING:   return "string";
        case JsonFieldType::BOOL:     return "boolean";
        case JsonFieldType::INTEGER:  return "integer";
        case JsonFieldType::UNSIGNED: return "unsigned";
        case JsonFieldType::DOUBLE:   return "number";
        case JsonFieldType::OBJECT:   return "object";
        case JsonFieldType::ARRAY:    return "array";
        case JsonFieldType::ANY:      return "any";
    }
    return "unknown";
}

// ===========================================================================
// Add requirements
// ===========================================================================

void JsonValidator::Require(const std::string& dot_path, JsonFieldType type) {
    m_fields.push_back({ dot_path, type, true });
}

void JsonValidator::RequireString(const std::string& p) {
    Require(p, JsonFieldType::STRING);
}
void JsonValidator::RequireBool(const std::string& p) {
    Require(p, JsonFieldType::BOOL);
}
void JsonValidator::RequireI64(const std::string& p) {
    Require(p, JsonFieldType::INTEGER);
}
void JsonValidator::RequireU32(const std::string& p) {
    Require(p, JsonFieldType::UNSIGNED);
}
void JsonValidator::RequireDouble(const std::string& p) {
    Require(p, JsonFieldType::DOUBLE);
}
void JsonValidator::RequireObject(const std::string& p) {
    Require(p, JsonFieldType::OBJECT);
}
void JsonValidator::RequireArray(const std::string& p) {
    Require(p, JsonFieldType::ARRAY);
}
void JsonValidator::RequireAny(const std::string& p) {
    Require(p, JsonFieldType::ANY);
}

void JsonValidator::Optional(const std::string& dot_path, JsonFieldType type) {
    m_fields.push_back({ dot_path, type, false });
}

// ===========================================================================
// Type check helper
// ===========================================================================

bool JsonValidator::CheckType(const nlohmann::json& node,
                               JsonFieldType type) const {
    switch (type) {
        case JsonFieldType::STRING:   return node.is_string();
        case JsonFieldType::BOOL:     return node.is_boolean();
        case JsonFieldType::INTEGER:  return node.is_number_integer() ||
                                             node.is_number_unsigned();
        case JsonFieldType::UNSIGNED: return node.is_number_unsigned() ||
                                            (node.is_number_integer() &&
                                             node.get<utils::i64>() >= 0);
        case JsonFieldType::DOUBLE:   return node.is_number();
        case JsonFieldType::OBJECT:   return node.is_object();
        case JsonFieldType::ARRAY:    return node.is_array();
        case JsonFieldType::ANY:      return true;
    }
    return false;
}

// ===========================================================================
// Validate
// ===========================================================================

std::vector<std::string>
JsonValidator::Validate(const JsonLoader& loader) const {
    std::vector<std::string> errors;

    for (const auto& spec : m_fields) {
        if (!loader.Has(spec.dot_path)) {
            if (spec.required) {
                errors.push_back(
                    "Missing required key: '" + spec.dot_path + "'");
            }
            continue;
        }

        // Key exists — check type

        // Re-navigate via loader
        try {
            // Use Sub trick for type check
            const auto& root = loader.Root();
            auto parts = utils::StringUtils::Split(spec.dot_path, '.');
            const nlohmann::json* cur = &root;
            bool nav_ok = true;
            for (const auto& p : parts) {
                if (!cur->is_object()) { nav_ok = false; break; }
                auto it = cur->find(p);
                if (it == cur->end()) { nav_ok = false; break; }
                cur = &(*it);
            }
            if (!nav_ok || !cur) {
                errors.push_back("Navigation failed for: '" +
                                 spec.dot_path + "'");
                continue;
            }
            if (!CheckType(*cur, spec.type)) {
                errors.push_back(
                    "Key '" + spec.dot_path + "' has wrong type: expected " +
                    JsonFieldTypeToString(spec.type) + ", got " +
                    std::string(cur->type_name()));
            }
        } catch (...) {
            errors.push_back("Error checking key: '" + spec.dot_path + "'");
        }
    }

    return errors;
}

void JsonValidator::ValidateOrThrow(const JsonLoader& loader) const {
    auto errors = Validate(loader);
    if (!errors.empty()) {
        std::string msg = "JSON validation failed (" +
                          std::to_string(errors.size()) + " error(s)):\n";
        for (const auto& e : errors) {
            msg += "  - " + e + "\n";
        }
        UAV_THROW(utils::ConfigException, msg);
    }
}

} // namespace json
} // namespace uav