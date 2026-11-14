/* SPDX-License-Identifier: Apache-2.0 */
#include "MetalRuntime.h"

#include <future>
#include <iostream>
#include <map>
#include <queue>
#include <random>
#include <set>
#include <stdexcept>

using namespace heavyai::metal;

void require(bool valid, const char* message) {
  if (!valid) {
    throw std::runtime_error(message);
  }
}

void check(const std::vector<GraphEdge>& edges,
           uint32_t nodes,
           const std::vector<uint32_t>& sources,
           const std::vector<uint32_t>& sinks,
           uint32_t limit) {
  const auto actual = executeGraph(edges, nodes, sources, sinks, limit);
  std::set<std::pair<uint32_t, uint32_t>> edge_set;
  for (const auto& edge : edges) {
    edge_set.emplace(edge.from, edge.to);
  }
  std::map<std::pair<uint32_t, uint32_t>, uint32_t> expected, found;
  for (uint32_t source = 0; source < sources.size(); ++source) {
    std::vector<uint32_t> distance(nodes, UINT32_MAX);
    distance[sources[source]] = 0;
    std::queue<uint32_t> frontier;
    frontier.push(sources[source]);
    while (!frontier.empty()) {
      const auto node = frontier.front();
      frontier.pop();
      if (distance[node] == limit) {
        continue;
      }
      for (const auto& edge : edges) {
        if (edge.from == node && distance[edge.to] == UINT32_MAX) {
          distance[edge.to] = distance[node] + 1;
          frontier.push(edge.to);
        }
      }
    }
    bool complete = true;
    for (const auto& edge : edges) {
      if (distance[edge.from] == limit && distance[edge.to] == UINT32_MAX) {
        complete = false;
      }
    }
    require(bool(actual.source_complete[source]) == complete,
            "Graph cutoff status differs from reference");
    for (uint32_t sink = 0; sink < sinks.size(); ++sink) {
      if (distance[sinks[sink]] != UINT32_MAX) {
        expected[{source, sink}] = distance[sinks[sink]];
      }
    }
  }
  for (const auto& path : actual.paths) {
    require(path.source_index < sources.size() && path.sink_index < sinks.size(),
            "Invalid terminal index");
    require(!path.nodes.empty() && path.nodes.front() == sources[path.source_index] &&
                path.nodes.back() == sinks[path.sink_index],
            "Invalid witness endpoints");
    for (size_t step = 1; step < path.nodes.size(); ++step) {
      require(edge_set.count({path.nodes[step - 1], path.nodes[step]}) != 0,
              "Witness contains a missing directed edge");
    }
    require(found
                .emplace(std::make_pair(path.source_index, path.sink_index),
                         path.nodes.size() - 1)
                .second,
            "Duplicate source-to-sink path");
  }
  require(found == expected,
          "Metal graph mappings or shortest distances differ from reference");
}

int main() {
  try {
    require(available(), "Metal is unavailable");
    const std::vector<GraphEdge> basic{
        {0, 1}, {0, 2}, {1, 3}, {2, 3}, {3, 1}, {3, 4}, {0, 1}};
    for (uint32_t limit = 0; limit < 7; ++limit) {
      check(basic, 7, {0, 4, 6}, {0, 1, 2, 3, 4, 6}, limit);
    }
    check({}, 3, {0, 1}, {0, 1, 2}, 3);
    check({}, 0, {}, {}, 0);
    std::mt19937 random(41);
    for (int iteration = 0; iteration < 20; ++iteration) {
      std::vector<GraphEdge> edges;
      for (int edge = 0; edge < 160; ++edge) {
        edges.push_back(
            {static_cast<uint32_t>(random() % 47), static_cast<uint32_t>(random() % 47)});
      }
      std::vector<uint32_t> sources, sinks;
      for (uint32_t node = 0; node < 50; ++node) {
        if (node < 19)
          sources.push_back(node);
        sinks.push_back(node);
      }
      check(edges, 50, sources, sinks, iteration % 9);
    }
    auto first = std::async(std::launch::async, [&] { check(basic, 7, {0}, {4}, 8); });
    auto second = std::async(std::launch::async, [&] {
      check(basic, 7, {4}, {0, 4}, 8);
    });
    first.get();
    second.get();
    bool rejected = false;
    try {
      executeGraph({{0, 2}}, 2, {0}, {1}, 4);
    } catch (const std::runtime_error&) {
      rejected = true;
    }
    require(rejected, "Invalid graph node was accepted");
    rejected = false;
    try {
      executeGraph({}, 1, {0}, {0}, 129);
    } catch (const std::runtime_error&) {
      rejected = true;
    }
    require(rejected, "Invalid hop bound was accepted");
    std::cout << "PASS: Metal directed mappings, shortest witness paths, cycles, "
                 "duplicate edges, isolated nodes, cutoffs, source batches, random "
                 "graphs, concurrent calls, and bounds\n"
              << "device=" << deviceName() << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "FAIL: " << error.what() << '\n';
    return 1;
  }
}
