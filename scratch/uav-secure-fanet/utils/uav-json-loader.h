/**
 * utils/uav-json-loader.h
 *
 * JSON file loader and accessor for the UAV Secure FANET project.
 *
 * Wraps nlohmann/json with:
 *   - Safe typed accessors that throw ConfigException on missing/wrong type
 *   - Optional accessors that return defaults without throwing
 *   - Large integer support via string<->cpp_int bridge (for CRT keys)
 *   - Merge support (overlay one JSON onto another)
 *   - Schema-key validation
 *
 * Usage:
 *   auto loader = uav::json::JsonLoader::FromFile("json/crypto_params.json");
 *   u32  n      = loader.GetU32("topology.num_uavs");
 *   auto key    = loader.GetBigInt("crypto.master_key");   // returns string
 *   bool dbg    = loader.GetBool("simulation.debug", false);
 */

#ifndef UAV_JSON_LOADER_H
#define UAV_JSON_LOADER_H

#include "uav-types.h"
#include "uav-error.h"

#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace uav {
namespace json {

using Json = nlohmann::json;

// ===========================================================================
// JsonLoader
// ===========================================================================
class JsonLoader {
public:
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Load from a file path. Throws ConfigException on IO or parse error.
    static JsonLoader FromFile(const std::string& path);

    /// Load from a JSON string. Throws ConfigException on parse error.
    static JsonLoader FromString(const std::string& json_str);

    /// Wrap an existing nlohmann::json object.
    explicit JsonLoader(Json root);

    /// Default — empty object.
    JsonLoader() : m_root(Json::object()) {}

    // -----------------------------------------------------------------------
    // Raw access
    // -----------------------------------------------------------------------

    /// Returns the root JSON object.
    const Json& Root() const { return m_root; }
    Json&       Root()       { return m_root; }

    /// Returns a sub-loader for a nested key (dot-separated path).
    /// Throws ConfigException if key does not exist or is not an object.
    JsonLoader Sub(const std::string& dot_path) const;

    /// Returns true if dot-separated key exists.
    bool Has(const std::string& dot_path) const;

    // -----------------------------------------------------------------------
    // Typed getters — throw ConfigException if key missing or wrong type
    // -----------------------------------------------------------------------
    std::string GetString(const std::string& dot_path) const;
    bool        GetBool  (const std::string& dot_path) const;
    utils::i64  GetI64   (const std::string& dot_path) const;
    utils::u64  GetU64   (const std::string& dot_path) const;
    utils::u32  GetU32   (const std::string& dot_path) const;
    double      GetDouble(const std::string& dot_path) const;

    /// Large integer stored as decimal string — used for CRT key parameters.
    /// Returns the raw string; caller converts to cpp_int.
    std::string GetBigInt(const std::string& dot_path) const;

    /// Array of strings.
    std::vector<std::string> GetStringArray(const std::string& dot_path) const;

    /// Array of u32.
    std::vector<utils::u32> GetU32Array(const std::string& dot_path) const;

    /// Array of doubles.
    std::vector<double> GetDoubleArray(const std::string& dot_path) const;

    // -----------------------------------------------------------------------
    // Optional getters — return default if key missing, throw on wrong type
    // -----------------------------------------------------------------------
    std::string GetString(const std::string& dot_path,
                          const std::string& def) const;
    bool        GetBool  (const std::string& dot_path, bool        def) const;
    utils::i64  GetI64   (const std::string& dot_path, utils::i64  def) const;
    utils::u64  GetU64   (const std::string& dot_path, utils::u64  def) const;
    utils::u32  GetU32   (const std::string& dot_path, utils::u32  def) const;
    double      GetDouble(const std::string& dot_path, double      def) const;
    std::string GetBigInt(const std::string& dot_path,
                          const std::string& def) const;

    // -----------------------------------------------------------------------
    // Merge / overlay
    // -----------------------------------------------------------------------
    /// Deep-merge another loader's root into this one.
    /// Keys in `other` override keys in `this`.
    void MergeFrom(const JsonLoader& other);

    // -----------------------------------------------------------------------
    // Serialisation
    // -----------------------------------------------------------------------
    /// Dump to pretty-printed JSON string.
    std::string Dump(int indent = 2) const;

    /// Write to file. Throws ConfigException on failure.
    void ToFile(const std::string& path, int indent = 2) const;

    // -----------------------------------------------------------------------
    // Array iteration helper
    // -----------------------------------------------------------------------
    /// Returns number of elements if root[dot_path] is an array, else 0.
    std::size_t ArraySize(const std::string& dot_path) const;

    /// Returns a loader for root[dot_path][index].
    /// Throws if path is not an array or index is out of range.
    JsonLoader ArrayElement(const std::string& dot_path,
                            std::size_t index) const;

private:
    /// Navigate dot-separated path, returning pointer to node or nullptr.
    const Json* Navigate(const std::string& dot_path) const;

    /// Navigate and throw ConfigException if not found.
    const Json& NavigateOrThrow(const std::string& dot_path) const;

    /// Deep merge helper (recursive).
    static void DeepMerge(Json& target, const Json& source);

    Json m_root;
};

} // namespace json
} // namespace uav

#endif // UAV_JSON_LOADER_H