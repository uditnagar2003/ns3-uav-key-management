/**
 * utils/uav-json-loader.cc
 */

#include "uav-json-loader.h"
#include "uav-file-utils.h"
#include "uav-string-utils.h"
#include "uav-logger.h"
#include "uav-log-channels.h"

#include <fstream>
#include <sstream>

namespace uav {
namespace json {

// ===========================================================================
// Construction
// ===========================================================================

JsonLoader JsonLoader::FromFile(const std::string& path) {
    if (!utils::FileUtils::Exists(path)) {
        UAV_THROW(utils::ConfigException,
                  "JsonLoader::FromFile: file not found: '" + path + "'");
    }

    std::string contents;
    try {
        contents = utils::FileUtils::ReadTextFile(path);
    } catch (const std::exception& ex) {
        UAV_THROW(utils::ConfigException,
                  "JsonLoader::FromFile: read error on '" + path +
                  "': " + ex.what());
    }

    try {
        Json root = Json::parse(contents);
        UAV_LOG_DEBUG(log::channels::SYSTEM,
                      "JsonLoader: loaded '" << path << "' ("
                      << contents.size() << " bytes)");
        return JsonLoader(std::move(root));
    } catch (const Json::parse_error& ex) {
        UAV_THROW(utils::ConfigException,
                  "JsonLoader::FromFile: JSON parse error in '" + path +
                  "': " + ex.what());
    }
}

JsonLoader JsonLoader::FromString(const std::string& json_str) {
    try {
        return JsonLoader(Json::parse(json_str));
    } catch (const Json::parse_error& ex) {
        UAV_THROW(utils::ConfigException,
                  std::string("JsonLoader::FromString: parse error: ") +
                  ex.what());
    }
}

JsonLoader::JsonLoader(Json root)
    : m_root(std::move(root))
{}

// ===========================================================================
// Navigation helpers
// ===========================================================================

const Json* JsonLoader::Navigate(const std::string& dot_path) const {
    auto parts = utils::StringUtils::Split(dot_path, '.');
    const Json* node = &m_root;
    for (const auto& part : parts) {
        if (!node->is_object()) return nullptr;
        auto it = node->find(part);
        if (it == node->end()) return nullptr;
        node = &(*it);
    }
    return node;
}

const Json& JsonLoader::NavigateOrThrow(const std::string& dot_path) const {
    const Json* node = Navigate(dot_path);
    if (!node) {
        UAV_THROW(utils::ConfigException,
                  "JSON key not found: '" + dot_path + "'");
    }
    return *node;
}

bool JsonLoader::Has(const std::string& dot_path) const {
    return Navigate(dot_path) != nullptr;
}

JsonLoader JsonLoader::Sub(const std::string& dot_path) const {
    const Json& node = NavigateOrThrow(dot_path);
    if (!node.is_object()) {
        UAV_THROW(utils::ConfigException,
                  "JSON key '" + dot_path + "' is not an object");
    }
    return JsonLoader(node);
}

// ===========================================================================
// Typed getters — mandatory
// ===========================================================================

std::string JsonLoader::GetString(const std::string& dot_path) const {
    const Json& node = NavigateOrThrow(dot_path);
    if (!node.is_string()) {
        UAV_THROW(utils::ConfigException,
                  "JSON key '" + dot_path + "' is not a string");
    }
    return node.get<std::string>();
}

bool JsonLoader::GetBool(const std::string& dot_path) const {
    const Json& node = NavigateOrThrow(dot_path);
    if (!node.is_boolean()) {
        UAV_THROW(utils::ConfigException,
                  "JSON key '" + dot_path + "' is not a boolean");
    }
    return node.get<bool>();
}

utils::i64 JsonLoader::GetI64(const std::string& dot_path) const {
    const Json& node = NavigateOrThrow(dot_path);
    if (!node.is_number_integer() && !node.is_number_unsigned()) {
        UAV_THROW(utils::ConfigException,
                  "JSON key '" + dot_path + "' is not an integer");
    }
    return node.get<utils::i64>();
}

utils::u64 JsonLoader::GetU64(const std::string& dot_path) const {
    const Json& node = NavigateOrThrow(dot_path);
    if (!node.is_number_unsigned() && !node.is_number_integer()) {
        UAV_THROW(utils::ConfigException,
                  "JSON key '" + dot_path + "' is not an unsigned integer");
    }
    return node.get<utils::u64>();
}

utils::u32 JsonLoader::GetU32(const std::string& dot_path) const {
    utils::u64 v = GetU64(dot_path);
    if (v > std::numeric_limits<utils::u32>::max()) {
        UAV_THROW(utils::ConfigException,
                  "JSON key '" + dot_path + "' value overflows u32");
    }
    return static_cast<utils::u32>(v);
}

double JsonLoader::GetDouble(const std::string& dot_path) const {
    const Json& node = NavigateOrThrow(dot_path);
    if (!node.is_number()) {
        UAV_THROW(utils::ConfigException,
                  "JSON key '" + dot_path + "' is not a number");
    }
    return node.get<double>();
}

std::string JsonLoader::GetBigInt(const std::string& dot_path) const {
    // Big integers are stored as decimal strings to avoid JSON number
    // precision loss (JSON numbers are 64-bit doubles).
    const Json& node = NavigateOrThrow(dot_path);
    if (node.is_string()) {
        return node.get<std::string>();
    }
    if (node.is_number_integer() || node.is_number_unsigned()) {
        // Small integer stored as JSON number — convert to string.
        return std::to_string(node.get<utils::u64>());
    }
    UAV_THROW(utils::ConfigException,
              "JSON key '" + dot_path +
              "' is not a string or integer (required for BigInt)");
}

std::vector<std::string>
JsonLoader::GetStringArray(const std::string& dot_path) const {
    const Json& node = NavigateOrThrow(dot_path);
    if (!node.is_array()) {
        UAV_THROW(utils::ConfigException,
                  "JSON key '" + dot_path + "' is not an array");
    }
    std::vector<std::string> out;
    out.reserve(node.size());
    for (const auto& el : node) {
        if (!el.is_string()) {
            UAV_THROW(utils::ConfigException,
                      "JSON array '" + dot_path +
                      "' contains non-string element");
        }
        out.push_back(el.get<std::string>());
    }
    return out;
}

std::vector<utils::u32>
JsonLoader::GetU32Array(const std::string& dot_path) const {
    const Json& node = NavigateOrThrow(dot_path);
    if (!node.is_array()) {
        UAV_THROW(utils::ConfigException,
                  "JSON key '" + dot_path + "' is not an array");
    }
    std::vector<utils::u32> out;
    out.reserve(node.size());
    for (const auto& el : node) {
        if (!el.is_number_unsigned() && !el.is_number_integer()) {
            UAV_THROW(utils::ConfigException,
                      "JSON array '" + dot_path +
                      "' contains non-integer element");
        }
        out.push_back(static_cast<utils::u32>(el.get<utils::u64>()));
    }
    return out;
}

std::vector<double>
JsonLoader::GetDoubleArray(const std::string& dot_path) const {
    const Json& node = NavigateOrThrow(dot_path);
    if (!node.is_array()) {
        UAV_THROW(utils::ConfigException,
                  "JSON key '" + dot_path + "' is not an array");
    }
    std::vector<double> out;
    out.reserve(node.size());
    for (const auto& el : node) {
        if (!el.is_number()) {
            UAV_THROW(utils::ConfigException,
                      "JSON array '" + dot_path +
                      "' contains non-number element");
        }
        out.push_back(el.get<double>());
    }
    return out;
}

// ===========================================================================
// Optional getters — return default if key missing
// ===========================================================================

std::string JsonLoader::GetString(const std::string& dot_path,
                                  const std::string& def) const {
    if (!Has(dot_path)) return def;
    return GetString(dot_path);
}

bool JsonLoader::GetBool(const std::string& dot_path, bool def) const {
    if (!Has(dot_path)) return def;
    return GetBool(dot_path);
}

utils::i64 JsonLoader::GetI64(const std::string& dot_path,
                               utils::i64 def) const {
    if (!Has(dot_path)) return def;
    return GetI64(dot_path);
}

utils::u64 JsonLoader::GetU64(const std::string& dot_path,
                               utils::u64 def) const {
    if (!Has(dot_path)) return def;
    return GetU64(dot_path);
}

utils::u32 JsonLoader::GetU32(const std::string& dot_path,
                               utils::u32 def) const {
    if (!Has(dot_path)) return def;
    return GetU32(dot_path);
}

double JsonLoader::GetDouble(const std::string& dot_path, double def) const {
    if (!Has(dot_path)) return def;
    return GetDouble(dot_path);
}

std::string JsonLoader::GetBigInt(const std::string& dot_path,
                                  const std::string& def) const {
    if (!Has(dot_path)) return def;
    return GetBigInt(dot_path);
}

// ===========================================================================
// Merge
// ===========================================================================

void JsonLoader::MergeFrom(const JsonLoader& other) {
    DeepMerge(m_root, other.m_root);
}

void JsonLoader::DeepMerge(Json& target, const Json& source) {
    if (!source.is_object() || !target.is_object()) {
        target = source;
        return;
    }
    for (auto it = source.begin(); it != source.end(); ++it) {
        if (target.contains(it.key()) &&
            target[it.key()].is_object() &&
            it.value().is_object()) {
            DeepMerge(target[it.key()], it.value());
        } else {
            target[it.key()] = it.value();
        }
    }
}

// ===========================================================================
// Serialisation
// ===========================================================================

std::string JsonLoader::Dump(int indent) const {
    return m_root.dump(indent);
}

void JsonLoader::ToFile(const std::string& path, int indent) const {
    try {
        utils::FileUtils::WriteTextFile(path, m_root.dump(indent) + "\n");
        UAV_LOG_DEBUG(log::channels::SYSTEM,
                      "JsonLoader: wrote '" << path << "'");
    } catch (const std::exception& ex) {
        UAV_THROW(utils::ConfigException,
                  "JsonLoader::ToFile: write error on '" + path +
                  "': " + ex.what());
    }
}

// ===========================================================================
// Array helpers
// ===========================================================================

std::size_t JsonLoader::ArraySize(const std::string& dot_path) const {
    const Json* node = Navigate(dot_path);
    if (!node || !node->is_array()) return 0;
    return node->size();
}

JsonLoader JsonLoader::ArrayElement(const std::string& dot_path,
                                    std::size_t index) const {
    const Json& node = NavigateOrThrow(dot_path);
    if (!node.is_array()) {
        UAV_THROW(utils::ConfigException,
                  "JSON key '" + dot_path + "' is not an array");
    }
    if (index >= node.size()) {
        UAV_THROW(utils::ConfigException,
                  "JSON array '" + dot_path + "' index " +
                  std::to_string(index) + " out of range (size=" +
                  std::to_string(node.size()) + ")");
    }
    return JsonLoader(node[index]);
}

} // namespace json
} // namespace uav