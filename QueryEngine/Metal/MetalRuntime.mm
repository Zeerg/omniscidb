/*
 * SPDX-License-Identifier: Apache-2.0
 */
#include "MetalRuntime.h"

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <unordered_map>

namespace heavyai::metal {
namespace {

struct Runtime {
  id<MTLDevice> device = MTLCreateSystemDefaultDevice();
  id<MTLCommandQueue> queue = device ? [device newCommandQueue] : nil;
  std::mutex mutex;
  std::unordered_map<std::string, id<MTLComputePipelineState>> pipelines;
};

Runtime& runtime() {
  static Runtime instance;
  return instance;
}

std::runtime_error metalError(const char* operation, NSError* error) {
  return std::runtime_error(std::string(operation) + ": " +
                            (error ? [[error localizedDescription] UTF8String]
                                   : "Metal resource allocation failed"));
}

id<MTLComputePipelineState> pipelineFor(const std::string& source,
                                        const char* entrypoint) {
  auto& state = runtime();
  const auto key = std::string(entrypoint) + "\n" + source;
  std::lock_guard<std::mutex> lock(state.mutex);
  const auto cached = state.pipelines.find(key);
  if (cached != state.pipelines.end()) {
    return cached->second;
  }
  NSError* error = nil;
  NSString* text = [[NSString alloc] initWithBytes:source.data()
                                            length:source.size()
                                          encoding:NSUTF8StringEncoding];
  MTLCompileOptions* options = [MTLCompileOptions new];
  options.mathMode = MTLMathModeSafe;
  id<MTLLibrary> library = [state.device newLibraryWithSource:text
                                                      options:options
                                                        error:&error];
  if (!library) {
    throw metalError("Metal query compilation", error);
  }
  id<MTLFunction> function =
      [library newFunctionWithName:[NSString stringWithUTF8String:entrypoint]];
  if (!function) {
    throw std::runtime_error("The compiled Metal query has no entry point");
  }
  auto pipeline = [state.device newComputePipelineStateWithFunction:function
                                                              error:&error];
  if (!pipeline) {
    throw metalError("Metal query pipeline creation", error);
  }
  if (state.pipelines.size() >= 64) {
    state.pipelines.clear();
  }
  state.pipelines.emplace(key, pipeline);
  return pipeline;
}

}  // namespace

bool available() {
  return runtime().device != nil && runtime().queue != nil;
}

std::string deviceName() {
  return available() ? [[runtime().device name] UTF8String] : "unavailable";
}

ScanResult executeScan(const ScanPlan& plan,
                       const std::vector<ColumnBuffer>& columns,
                       size_t row_count) {
  @autoreleasepool {
    if (!available()) {
      throw std::runtime_error("No Metal compute device is available");
    }
    if (columns.size() != plan.columns.size()) {
      throw std::invalid_argument("Metal input column count does not match the plan");
    }
    const auto source = compileScan(plan);
    auto& state = runtime();
    size_t input_bytes = 0;
    for (size_t i = 0; i < columns.size(); ++i) {
      const auto width = integerWidth(plan.columns[i]);
      if (row_count > std::numeric_limits<size_t>::max() / width ||
          columns[i].bytes < row_count * width ||
          (row_count && columns[i].data == nullptr) ||
          columns[i].bytes > [state.device maxBufferLength] ||
          columns[i].bytes > [state.device recommendedMaxWorkingSetSize] - input_bytes) {
        throw std::runtime_error("Metal input exceeds its buffer or memory limit");
      }
      input_bytes += columns[i].bytes;
    }
    if (row_count == 0) {
      return {};
    }

    const auto pipeline = pipelineFor(source, "heavydb_scan");

    const uint32_t threads = static_cast<uint32_t>(std::min(row_count, size_t(4096)));
    const size_t output_count = size_t(threads) * plan.aggregates.size();
    id<MTLBuffer> output =
        [state.device newBufferWithLength:output_count * sizeof(Partial)
                                  options:MTLResourceStorageModeShared];
    id<MTLCommandBuffer> command = [state.queue commandBuffer];
    command.label = @"HeavyDB Metal SQL aggregate";
    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
    if (!output || !command || !encoder) {
      throw metalError("Metal query resource creation", nil);
    }
    [encoder setComputePipelineState:pipeline];
    std::vector<id<MTLBuffer>> buffers;
    for (size_t i = 0; i < columns.size(); ++i) {
      id<MTLBuffer> buffer =
          [state.device newBufferWithBytes:columns[i].data
                                    length:columns[i].bytes
                                   options:MTLResourceStorageModeShared];
      if (!buffer) {
        [encoder endEncoding];
        throw metalError("Metal input buffer creation", nil);
      }
      buffers.push_back(buffer);
      [encoder setBuffer:buffer offset:0 atIndex:i];
    }
    const uint64_t rows = row_count;
    [encoder setBuffer:output offset:0 atIndex:columns.size()];
    [encoder setBytes:&rows length:sizeof(rows) atIndex:columns.size() + 1];
    [encoder setBytes:&threads length:sizeof(threads) atIndex:columns.size() + 2];
    [encoder dispatchThreads:MTLSizeMake(threads, 1, 1)
        threadsPerThreadgroup:MTLSizeMake(
                                  std::min(NSUInteger(256),
                                           [pipeline maxTotalThreadsPerThreadgroup]),
                                  1,
                                  1)];
    [encoder endEncoding];
    [command commit];
    [command waitUntilCompleted];
    if ([command status] != MTLCommandBufferStatusCompleted) {
      throw metalError("Metal query execution", [command error]);
    }

    ScanResult result;
    result.partials.resize(output_count);
    std::memcpy(
        result.partials.data(), [output contents], output_count * sizeof(Partial));
    result.gpu_time_ms = ([command GPUEndTime] - [command GPUStartTime]) * 1000.0;
    return result;
  }
}

GraphResult executeGraph(const std::vector<GraphEdge>& edges,
                         uint32_t node_count,
                         const std::vector<uint32_t>& sources,
                         const std::vector<uint32_t>& sinks,
                         uint32_t max_hops) {
  @autoreleasepool {
    if (!available()) {
      throw std::runtime_error("No Metal compute device is available");
    }
    if (node_count > 1000000 || edges.size() > 2000000 || sources.size() > 4096 ||
        sinks.size() > 4096 || max_hops > 128) {
      throw std::runtime_error(
          "Metal graph input exceeds its node, edge, terminal, or hop limit");
    }
    for (const auto& edge : edges) {
      if (edge.from >= node_count || edge.to >= node_count) {
        throw std::runtime_error("Metal graph edge has an invalid node index");
      }
    }
    for (const auto node : sources) {
      if (node >= node_count) {
        throw std::runtime_error("Metal graph source has an invalid node index");
      }
    }
    for (const auto node : sinks) {
      if (node >= node_count) {
        throw std::runtime_error("Metal graph sink has an invalid node index");
      }
    }
    const auto work =
        (uint64_t(edges.size()) * (max_hops + 1) + node_count) * sources.size();
    if (work > 1000000000) {
      throw std::runtime_error("Metal graph exceeds its 1B work-item budget; narrow the "
                               "cursors or reduce max_hops");
    }
    GraphResult result;
    result.source_complete.resize(sources.size());
    if (sources.empty()) {
      return result;
    }
    const std::string source = R"METAL(
#include <metal_stdlib>
using namespace metal;
kernel void heavydb_graph_init(device atomic_uint* depth [[buffer(0)]],
                              device atomic_uint* parent [[buffer(1)]],
                              device const uint* sources [[buffer(2)]],
                              device atomic_uint* complete [[buffer(3)]],
                              constant uint& n [[buffer(4)]],
                              constant uint& batch [[buffer(5)]],
                              uint i [[thread_position_in_grid]]) {
  uint root = sources[i / n];
  bool is_root = (i % n == root);
  atomic_store_explicit(depth + i, is_root ? 0u : 0xffffffffu, memory_order_relaxed);
  atomic_store_explicit(parent + i, is_root ? root : 0xffffffffu, memory_order_relaxed);
  if (i < batch) atomic_store_explicit(complete + i, 1u, memory_order_relaxed);
}
kernel void heavydb_graph_step(device const uint2* edges [[buffer(0)]],
                              device atomic_uint* depth [[buffer(1)]],
                              device atomic_uint* parent [[buffer(2)]],
                              constant uint& n [[buffer(3)]],
                              constant uint& round [[buffer(4)]],
                              uint2 i [[thread_position_in_grid]]) {
  uint2 edge = edges[i.x];
  uint from = i.y * n + edge.x, to = i.y * n + edge.y;
  if (atomic_load_explicit(depth + from, memory_order_relaxed) == round) {
    uint old = atomic_fetch_min_explicit(depth + to, round + 1u, memory_order_relaxed);
    if (old >= round + 1u)
      atomic_fetch_min_explicit(parent + to, edge.x, memory_order_relaxed);
  }
}
kernel void heavydb_graph_cutoff(device const uint2* edges [[buffer(0)]],
                                device atomic_uint* depth [[buffer(1)]],
                                device atomic_uint* complete [[buffer(2)]],
                                constant uint& n [[buffer(3)]],
                                constant uint& limit [[buffer(4)]],
                                uint2 i [[thread_position_in_grid]]) {
  uint2 edge = edges[i.x];
  if (atomic_load_explicit(depth + i.y * n + edge.x, memory_order_relaxed) == limit &&
      atomic_load_explicit(depth + i.y * n + edge.y, memory_order_relaxed) == 0xffffffffu)
    atomic_store_explicit(complete + i.y, 0u, memory_order_relaxed);
}
)METAL";
    const auto initialize = pipelineFor(source, "heavydb_graph_init");
    const auto advance = pipelineFor(source, "heavydb_graph_step");
    const auto cutoff = pipelineFor(source, "heavydb_graph_cutoff");
    auto& state = runtime();
    const size_t edge_bytes =
        std::max(sizeof(GraphEdge), edges.size() * sizeof(GraphEdge));
    const size_t batch_limit = std::min(size_t(16), sources.size());
    const size_t state_bytes = size_t(node_count) * batch_limit * sizeof(uint32_t);
    if (edge_bytes > [state.device maxBufferLength] ||
        state_bytes > [state.device maxBufferLength] ||
        edge_bytes + state_bytes * 2 + batch_limit * 8 >
            std::min(size_t(256) << 20,
                     size_t([state.device recommendedMaxWorkingSetSize]))) {
      throw std::runtime_error(
          "Metal graph exceeds its device buffer or 256 MiB working-set limit");
    }
    id<MTLBuffer> edge_buffer =
        [state.device newBufferWithLength:edge_bytes
                                  options:MTLResourceStorageModeShared];
    if (!edge_buffer) {
      throw metalError("Metal graph edge buffer creation", nil);
    }
    if (!edges.empty()) {
      std::memcpy([edge_buffer contents], edges.data(), edges.size() * sizeof(GraphEdge));
    }
    const auto group_width = std::min({NSUInteger(256),
                                       [initialize maxTotalThreadsPerThreadgroup],
                                       [advance maxTotalThreadsPerThreadgroup],
                                       [cutoff maxTotalThreadsPerThreadgroup]});
    size_t output_rows = 0;
    for (size_t begin = 0; begin < sources.size(); begin += batch_limit) {
      const uint32_t batch = std::min(batch_limit, sources.size() - begin);
      const size_t bytes = size_t(node_count) * batch * sizeof(uint32_t);
      id<MTLBuffer> depths =
          [state.device newBufferWithLength:bytes options:MTLResourceStorageModeShared];
      id<MTLBuffer> parents =
          [state.device newBufferWithLength:bytes options:MTLResourceStorageModeShared];
      id<MTLBuffer> roots =
          [state.device newBufferWithBytes:sources.data() + begin
                                    length:batch * sizeof(uint32_t)
                                   options:MTLResourceStorageModeShared];
      id<MTLBuffer> complete =
          [state.device newBufferWithLength:batch * sizeof(uint32_t)
                                    options:MTLResourceStorageModeShared];
      if (!depths || !parents || !roots || !complete) {
        throw metalError("Metal graph state buffer creation", nil);
      }
      id<MTLCommandBuffer> command = [state.queue commandBuffer];
      command.label = @"HeavyDB Metal graph reachability";
      id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
      if (!command || !encoder) {
        throw metalError("Metal graph command creation", nil);
      }
      const auto dispatch = [&](size_t x, size_t y) {
        [encoder dispatchThreads:MTLSizeMake(x, y, 1)
            threadsPerThreadgroup:MTLSizeMake(group_width, 1, 1)];
        [encoder memoryBarrierWithScope:MTLBarrierScopeBuffers];
      };
      [encoder setComputePipelineState:initialize];
      [encoder setBuffer:depths offset:0 atIndex:0];
      [encoder setBuffer:parents offset:0 atIndex:1];
      [encoder setBuffer:roots offset:0 atIndex:2];
      [encoder setBuffer:complete offset:0 atIndex:3];
      [encoder setBytes:&node_count length:sizeof(node_count) atIndex:4];
      [encoder setBytes:&batch length:sizeof(batch) atIndex:5];
      dispatch(size_t(node_count) * batch, 1);
      if (!edges.empty()) {
        [encoder setComputePipelineState:advance];
        [encoder setBuffer:edge_buffer offset:0 atIndex:0];
        [encoder setBuffer:depths offset:0 atIndex:1];
        [encoder setBuffer:parents offset:0 atIndex:2];
        [encoder setBytes:&node_count length:sizeof(node_count) atIndex:3];
        // A dispatch barrier separates BFS levels. New nodes do not run in this level.
        for (uint32_t round = 0; round < max_hops; ++round) {
          [encoder setBytes:&round length:sizeof(round) atIndex:4];
          dispatch(edges.size(), batch);
        }
        [encoder setComputePipelineState:cutoff];
        [encoder setBuffer:complete offset:0 atIndex:2];
        [encoder setBytes:&max_hops length:sizeof(max_hops) atIndex:4];
        dispatch(edges.size(), batch);
      }
      [encoder endEncoding];
      [command commit];
      [command waitUntilCompleted];
      if ([command status] != MTLCommandBufferStatusCompleted) {
        throw metalError("Metal graph execution", [command error]);
      }
      result.gpu_time_ms += ([command GPUEndTime] - [command GPUStartTime]) * 1000.0;
      const auto* distance = static_cast<const uint32_t*>([depths contents]);
      const auto* parent = static_cast<const uint32_t*>([parents contents]);
      const auto* completed = static_cast<const uint32_t*>([complete contents]);
      for (uint32_t local = 0; local < batch; ++local) {
        result.source_complete[begin + local] = completed[local];
        for (size_t sink = 0; sink < sinks.size(); ++sink) {
          const auto hops = distance[size_t(local) * node_count + sinks[sink]];
          if (hops == UINT32_MAX) {
            continue;
          }
          output_rows += size_t(hops) + 1;
          if (output_rows > 1000000) {
            throw std::runtime_error(
                "Metal graph output exceeds 1M path rows; narrow the cursors");
          }
          GraphPath path{static_cast<uint32_t>(begin + local),
                         static_cast<uint32_t>(sink),
                         std::vector<uint32_t>(size_t(hops) + 1)};
          auto current = sinks[sink];
          for (int32_t step = hops; step >= 0; --step) {
            path.nodes[step] = current;
            if (step) {
              const auto previous = parent[size_t(local) * node_count + current];
              if (previous >= node_count ||
                  distance[size_t(local) * node_count + previous] + 1 != uint32_t(step)) {
                throw std::runtime_error(
                    "Metal graph returned an invalid witness predecessor");
              }
              current = previous;
            }
          }
          if (path.nodes.front() != sources[begin + local]) {
            throw std::runtime_error("Metal graph witness does not start at its source");
          }
          result.paths.push_back(std::move(path));
        }
      }
    }
    return result;
  }
}

}  // namespace heavyai::metal
