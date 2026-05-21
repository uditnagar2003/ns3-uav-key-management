/**
 * mobility/uav-gauss-markov.h
 * Module 31 - GaussMarkov per-UAV speed configuration
 */

#ifndef UAV_GAUSS_MARKOV_H
#define UAV_GAUSS_MARKOV_H

#include "uav-mobility-manager.h"
#include "uav-types.h"
#include <vector>
#include <string>

namespace uav {
namespace mobility {

struct GaussMarkovConfig {
    double alpha           = 0.85;
    double mean_velocity   = 15.0;
    double velocity_var    = 3.0;
    double time_step_s     = 0.5;
    double cohesion_radius = 300.0;
};

class GaussMarkovManager {
public:
    explicit GaussMarkovManager(
        const routing::TopologyResult& topo,
        const GaussMarkovConfig& cfg = GaussMarkovConfig{});

    void RandomizeUavSpeeds(double min_mps,
                             double max_mps,
                             utils::u32 seed = 42);

    double GetUavSpeed(utils::u32 uav_index) const;

    bool IsWithinCohesion(utils::u32 uav_index,
                           utils::u32 cluster) const;

    void PrintSpeedSummary() const;

    const GaussMarkovConfig& GetConfig() const {
        return m_cfg;
    }

private:
    const routing::TopologyResult& m_topo;
    GaussMarkovConfig              m_cfg;
    std::vector<double>            m_uav_speeds;
};

} // namespace mobility
} // namespace uav

#endif // UAV_GAUSS_MARKOV_H
