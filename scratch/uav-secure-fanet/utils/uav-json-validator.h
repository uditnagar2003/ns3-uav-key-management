/**
 * utils/uav-json-validator.h
 *
 * Lightweight JSON schema validator.
 *
 * Validates that required keys exist and have the correct types.
 * Used by ConfigManager (Module 6) and JsonCryptoParser (Module 14)
 * to catch malformed JSON files before the simulation starts.
 *
 * Usage:
 *   JsonValidator v;
 *   v.RequireString("topology.scheme");
 *   v.RequireU32("topology.num_uavs");
 *   v.RequireBool("simulation.debug");
 *   v.RequireArray("crypto.slaves");
 *
 *   auto errors = v.Validate(loader);
 *   if (!errors.empty()) { ... }
 */

#ifndef UAV_JSON_VALIDATOR_H
#define UAV_JSON_VALIDATOR_H

#include "uav-json-loader.h"
#include <string>
#include <vector>

namespace uav {
namespace json {

// ===========================================================================
// Expected field type
// ===========================================================================
enum class JsonFieldType {
    STRING,
    BOOL,
    INTEGER,
    UNSIGNED,
    DOUBLE,
    OBJECT,
    ARRAY,
    ANY
};

const char* JsonFieldTypeToString(JsonFieldType t);

// ===========================================================================
// JsonValidator
// ===========================================================================
class JsonValidator {
public:
    // -----------------------------------------------------------------------
    // Add required fields
    // -----------------------------------------------------------------------
    void Require   (const std::string& dot_path, JsonFieldType type);
    void RequireString  (const std::string& dot_path);
    void RequireBool    (const std::string& dot_path);
    void RequireI64     (const std::string& dot_path);
    void RequireU32     (const std::string& dot_path);
    void RequireDouble  (const std::string& dot_path);
    void RequireObject  (const std::string& dot_path);
    void RequireArray   (const std::string& dot_path);
    void RequireAny     (const std::string& dot_path);

    // -----------------------------------------------------------------------
    // Add optional fields (type-checked if present)
    // -----------------------------------------------------------------------
    void Optional  (const std::string& dot_path, JsonFieldType type);

    // -----------------------------------------------------------------------
    // Validate
    // Returns list of error strings. Empty = valid.
    // -----------------------------------------------------------------------
    std::vector<std::string> Validate(const JsonLoader& loader) const;

    /// Validate and throw ConfigException on first error.
    void ValidateOrThrow(const JsonLoader& loader) const;

    /// Clear all requirements.
    void Clear() { m_fields.clear(); }

private:
    struct FieldSpec {
        std::string   dot_path;
        JsonFieldType type;
        bool          required;
    };

    bool CheckType(const nlohmann::json& node, JsonFieldType type) const;

    std::vector<FieldSpec> m_fields;
};

} // namespace json
} // namespace uav

#endif // UAV_JSON_VALIDATOR_H