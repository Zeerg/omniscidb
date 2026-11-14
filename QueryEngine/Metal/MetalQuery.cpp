/*
 * SPDX-License-Identifier: Apache-2.0
 */
#include "MetalRuntime.h"

#include <limits>
#include <sstream>
#include <stdexcept>

namespace heavyai::metal {

size_t integerWidth(IntegerType type) {
  switch (type) {
    case IntegerType::Int8:
      return 1;
    case IntegerType::Int16:
      return 2;
    case IntegerType::Int32:
      return 4;
    case IntegerType::Int64:
      return 8;
  }
  throw std::invalid_argument("Invalid Metal integer type");
}

std::string compileScan(const ScanPlan& plan) {
  if (plan.columns.size() > 28 || plan.aggregates.empty() ||
      plan.aggregates.size() > 64 || plan.predicate.empty()) {
    throw std::invalid_argument("Invalid Metal aggregate plan");
  }
  std::ostringstream source;
  source << "#include <metal_stdlib>\nusing namespace metal;\n"
            "struct Partial { long value; ulong count; ulong overflow; };\n"
            "kernel void heavydb_scan(";
  for (size_t i = 0; i < plan.columns.size(); ++i) {
    const char* type = nullptr;
    switch (plan.columns[i]) {
      case IntegerType::Int8:
        type = "char";
        break;
      case IntegerType::Int16:
        type = "short";
        break;
      case IntegerType::Int32:
        type = "int";
        break;
      case IntegerType::Int64:
        type = "long";
        break;
    }
    source << "device const " << type << "* c" << i << " [[buffer(" << i << ")]],";
  }
  const auto output_index = plan.columns.size();
  source << "device Partial* output [[buffer(" << output_index << ")]],"
         << "constant ulong& rows [[buffer(" << output_index + 1 << ")]],"
         << "constant uint& threads [[buffer(" << output_index + 2 << ")]],"
         << "uint tid [[thread_position_in_grid]]) {\n";
  for (size_t i = 0; i < plan.aggregates.size(); ++i) {
    source << "long s" << i << "=0; ulong n" << i << "=0; ulong e" << i << "=0;\n";
  }
  source << "for (ulong row=tid; row<rows; row+=threads) {\n"
         << "if (" << plan.predicate << ") {\n";
  for (size_t i = 0; i < plan.aggregates.size(); ++i) {
    const auto& agg = plan.aggregates[i];
    source << "if (" << agg.valid << ") { long v=long(" << agg.value << ");\n";
    switch (agg.kind) {
      case AggregateKind::Count:
        break;
      case AggregateKind::Sum:
      case AggregateKind::Avg:
        source << "if ((v>0 && s" << i << ">LONG_MAX-v) || (v<0 && s" << i
               << "<LONG_MIN-v)) { e" << i << "=1; } else { s" << i << "+=v; }\n";
        break;
      case AggregateKind::Min:
        source << "if (n" << i << "==0 || v<s" << i << ") s" << i << "=v;\n";
        break;
      case AggregateKind::Max:
        source << "if (n" << i << "==0 || v>s" << i << ") s" << i << "=v;\n";
        break;
    }
    source << "++n" << i << "; }\n";
  }
  source << "}\n}\n";
  for (size_t i = 0; i < plan.aggregates.size(); ++i) {
    source << "output[ulong(tid)*" << plan.aggregates.size() << "+" << i << "]=Partial{s"
           << i << ",n" << i << ",e" << i << "};\n";
  }
  source << "}\n";
  return source.str();
}

void mergePartials(std::vector<Partial>& result,
                   const std::vector<Partial>& partials,
                   const std::vector<Aggregate>& aggregates) {
  if (aggregates.empty() || partials.size() % aggregates.size() != 0) {
    throw std::invalid_argument("Invalid Metal partial aggregate layout");
  }
  if (result.empty()) {
    result.resize(aggregates.size());
  }
  if (result.size() != aggregates.size()) {
    throw std::invalid_argument("Invalid Metal aggregate result layout");
  }
  for (size_t i = 0; i < partials.size(); ++i) {
    auto& total = result[i % result.size()];
    const auto& partial = partials[i];
    if (partial.overflow || partial.count > uint64_t(INT64_MAX) - total.count) {
      throw std::overflow_error("Metal SQL aggregate overflow");
    }
    if (partial.count == 0) {
      continue;
    }
    switch (aggregates[i % result.size()].kind) {
      case AggregateKind::Count:
        break;
      case AggregateKind::Sum:
      case AggregateKind::Avg:
        if (__builtin_add_overflow(total.value, partial.value, &total.value)) {
          throw std::overflow_error("Metal SQL aggregate overflow");
        }
        break;
      case AggregateKind::Min:
        if (total.count == 0 || partial.value < total.value) {
          total.value = partial.value;
        }
        break;
      case AggregateKind::Max:
        if (total.count == 0 || partial.value > total.value) {
          total.value = partial.value;
        }
        break;
    }
    total.count += partial.count;
  }
}

}  // namespace heavyai::metal
