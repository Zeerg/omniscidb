/*
 * SPDX-License-Identifier: Apache-2.0
 */
#include "MetalRuntime.h"

#include <iostream>
#include <limits>
#include <stdexcept>
#include <thread>

using namespace heavyai::metal;

void require(bool condition, const char* message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

int main() {
  try {
    require(available(), "Metal is unavailable");
    const auto null = std::numeric_limits<int64_t>::min();
    std::vector<int64_t> values(100003);
    uint64_t expected_count = 0;
    int64_t expected_sum = 0;
    int64_t expected_min = INT64_MAX;
    int64_t expected_max = INT64_MIN;
    for (size_t i = 0; i < values.size(); ++i) {
      values[i] = i % 97 == 0 ? null : int64_t(i % 1000) - 500;
      if (values[i] >= -100 && values[i] < 200) {
        ++expected_count;
        expected_sum += values[i];
        expected_min = std::min(expected_min, values[i]);
        expected_max = std::max(expected_max, values[i]);
      }
    }
    ScanPlan plan{{IntegerType::Int64},
                  "c0[row]>=-100L && c0[row]<200L",
                  {{AggregateKind::Count, "0L", "true"},
                   {AggregateKind::Sum, "c0[row]", "true"},
                   {AggregateKind::Min, "c0[row]", "true"},
                   {AggregateKind::Max, "c0[row]", "true"},
                   {AggregateKind::Avg, "c0[row]", "true"}}};
    const std::vector<ColumnBuffer> input{
        {values.data(), values.size() * sizeof(int64_t)}};
    auto scan = executeScan(plan, input, values.size());
    std::vector<Partial> result;
    mergePartials(result, scan.partials, plan.aggregates);
    require(result[0].count == expected_count, "COUNT mismatch");
    require(result[1].value == expected_sum, "SUM mismatch");
    require(result[2].value == expected_min, "MIN mismatch");
    require(result[3].value == expected_max, "MAX mismatch");
    require(result[4].value == expected_sum && result[4].count == expected_count,
            "AVG partials mismatch");
    require(executeScan(plan, {{nullptr, 0}}, 0).partials.empty(), "Empty scan mismatch");

    ScanPlan null_plan{{IntegerType::Int64},
                       "true",
                       {{AggregateKind::Count, "c0[row]", "c0[row]!=LONG_MIN"}}};
    std::vector<Partial> counts;
    mergePartials(counts,
                  executeScan(null_plan, input, values.size()).partials,
                  null_plan.aggregates);
    require(counts[0].count == values.size() - (values.size() + 96) / 97,
            "NULL count mismatch");

    ScanPlan sum_plan{
        {IntegerType::Int64}, "true", {{AggregateKind::Sum, "c0[row]", "true"}}};
    std::vector<int64_t> overflow_values(4097, 0);
    overflow_values[0] = INT64_MAX;
    overflow_values[4096] = 1;
    bool overflow_detected = false;
    try {
      auto partials = executeScan(sum_plan,
                                  {{overflow_values.data(), overflow_values.size() * 8}},
                                  overflow_values.size());
      std::vector<Partial> sum;
      mergePartials(sum, partials.partials, sum_plan.aggregates);
    } catch (const std::overflow_error&) {
      overflow_detected = true;
    }
    require(overflow_detected, "GPU integer overflow was not detected");

    bool bad_buffer_rejected = false;
    try {
      executeScan(plan, {{values.data(), 8}}, values.size());
    } catch (const std::runtime_error&) {
      bad_buffer_rejected = true;
    }
    require(bad_buffer_rejected, "Undersized input was not rejected");
    std::cout << "device=" << deviceName() << "\n"
              << "PASS: filtered COUNT/SUM/MIN/MAX/AVG, NULLs, empty input, "
                 "integer overflow, input bounds\n"
              << "rows=" << values.size() << " gpu_ms=" << scan.gpu_time_ms << "\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "FAIL: " << error.what() << '\n';
    return 1;
  }
}
