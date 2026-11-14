/* SPDX-License-Identifier: Apache-2.0 */
#include "MetalGraphTableFunctions.h"

#include "Logger/Logger.h"
#include "MetalExecutor.h"
#include "MetalRuntime.h"

#include <algorithm>
#include <stdexcept>
#include <unordered_map>

int32_t tf_metal_graph_paths__cpu_(TableFunctionManager& mgr,
                                   const Column<int64_t>& edge_from,
                                   const Column<int64_t>& edge_to,
                                   const Column<int64_t>& source_nodes,
                                   const Column<int64_t>& sink_nodes,
                                   const int32_t max_hops,
                                   Column<int64_t>& output_source,
                                   Column<int64_t>& output_sink,
                                   Column<int64_t>& output_node,
                                   Column<int32_t>& output_step,
                                   Column<int32_t>& output_hops,
                                   Column<bool>& output_complete) {
  try {
    if (!g_enable_metal || !heavyai::metal::available()) {
      throw std::runtime_error(
          "tf_metal_graph_paths requires --enable-metal and a Metal device; no CPU "
          "traversal fallback");
    }
    if (edge_from.size() != edge_to.size() || edge_from.size() > 2000000 ||
        source_nodes.size() > 4096 || sink_nodes.size() > 4096 || max_hops < 0 ||
        max_hops > 128) {
      throw std::runtime_error(
          "Metal graph limits: 2M edges, 4096 sources, 4096 sinks, and 0..128 hops");
    }
    std::unordered_map<int64_t, uint32_t> mapping;
    std::vector<int64_t> identifiers;
    const auto index = [&](const Column<int64_t>& column, int64_t row) {
      if (column.isNull(row)) {
        throw std::runtime_error("Metal graph node IDs cannot be NULL");
      }
      const auto found = mapping.find(column[row]);
      if (found != mapping.end()) {
        return found->second;
      }
      if (identifiers.size() >= 1000000) {
        throw std::runtime_error("Metal graph exceeds 1M distinct node IDs");
      }
      const auto identifier = static_cast<uint32_t>(identifiers.size());
      mapping.emplace(column[row], identifier);
      identifiers.push_back(column[row]);
      return identifier;
    };
    std::vector<heavyai::metal::GraphEdge> edges;
    edges.reserve(edge_from.size());
    for (int64_t row = 0; row < edge_from.size(); ++row) {
      edges.push_back({index(edge_from, row), index(edge_to, row)});
    }
    const auto terminals = [&](const Column<int64_t>& column) {
      std::vector<uint32_t> result;
      for (int64_t row = 0; row < column.size(); ++row) {
        result.push_back(index(column, row));
      }
      std::sort(result.begin(), result.end());
      result.erase(std::unique(result.begin(), result.end()), result.end());
      return result;
    };
    const auto sources = terminals(source_nodes);
    const auto sinks = terminals(sink_nodes);
    const auto result = heavyai::metal::executeGraph(
        edges, static_cast<uint32_t>(identifiers.size()), sources, sinks, max_hops);
    std::vector<bool> matched(sources.size(), false);
    size_t rows = 0;
    for (const auto& path : result.paths) {
      matched[path.source_index] = true;
      rows += path.nodes.size();
    }
    rows += std::count(matched.begin(), matched.end(), false);
    if (rows > 1000000) {
      throw std::runtime_error(
          "Metal graph output exceeds 1M rows; narrow the input cursors");
    }
    mgr.set_output_row_size(rows);
    int32_t row = 0;
    for (const auto& path : result.paths) {
      for (size_t step = 0; step < path.nodes.size(); ++step, ++row) {
        output_source[row] = identifiers[sources[path.source_index]];
        output_sink[row] = identifiers[sinks[path.sink_index]];
        output_node[row] = identifiers[path.nodes[step]];
        output_step[row] = step;
        output_hops[row] = path.nodes.size() - 1;
        output_complete[row] = result.source_complete[path.source_index];
      }
    }
    for (size_t source = 0; source < sources.size(); ++source) {
      if (!matched[source]) {
        output_source[row] = identifiers[sources[source]];
        output_sink.setNull(row);
        output_node.setNull(row);
        output_step.setNull(row);
        output_hops.setNull(row);
        output_complete[row++] = result.source_complete[source];
      }
    }
    LOG(INFO) << "Metal graph executed: nodes=" << identifiers.size()
              << " edges=" << edges.size() << " sources=" << sources.size()
              << " sinks=" << sinks.size() << " max_hops=" << max_hops << " rows=" << row
              << " gpu_ms=" << result.gpu_time_ms
              << " device=" << heavyai::metal::deviceName();
    return row;
  } catch (const std::exception& error) {
    return mgr.error_message(error.what());
  }
}
