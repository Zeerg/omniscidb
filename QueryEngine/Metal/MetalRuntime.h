/*
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace heavyai::metal {

enum class IntegerType { Int8, Int16, Int32, Int64 };
enum class AggregateKind { Count, Sum, Min, Max, Avg };

struct Aggregate {
  AggregateKind kind;
  std::string value;
  std::string valid;
};

struct ScanPlan {
  std::vector<IntegerType> columns;
  std::string predicate;
  std::vector<Aggregate> aggregates;
};

struct ColumnBuffer {
  const void* data;
  size_t bytes;
};

// Keep this layout identical to Partial in the generated Metal source.
struct Partial {
  int64_t value{0};
  uint64_t count{0};
  uint64_t overflow{0};
};
static_assert(sizeof(Partial) == 24);

struct ScanResult {
  std::vector<Partial> partials;
  double gpu_time_ms{0};
};

struct GraphEdge {
  uint32_t from;
  uint32_t to;
};
static_assert(sizeof(GraphEdge) == 8);

struct GraphPath {
  uint32_t source_index;
  uint32_t sink_index;
  std::vector<uint32_t> nodes;
};

struct GraphResult {
  std::vector<GraphPath> paths;
  std::vector<uint8_t> source_complete;
  double gpu_time_ms{0};
};

bool available();
std::string deviceName();
size_t integerWidth(IntegerType type);
std::string compileScan(const ScanPlan& plan);
ScanResult executeScan(const ScanPlan& plan,
                       const std::vector<ColumnBuffer>& columns,
                       size_t row_count);
GraphResult executeGraph(const std::vector<GraphEdge>& edges,
                         uint32_t node_count,
                         const std::vector<uint32_t>& sources,
                         const std::vector<uint32_t>& sinks,
                         uint32_t max_hops);
void mergePartials(std::vector<Partial>& result,
                   const std::vector<Partial>& partials,
                   const std::vector<Aggregate>& aggregates);

}  // namespace heavyai::metal
