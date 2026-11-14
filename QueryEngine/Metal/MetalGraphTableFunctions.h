/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include "QueryEngine/heavydbTypes.h"

/*
  UDTF: tf_metal_graph_paths__cpu_(TableFunctionManager,
    Cursor<Column<int64_t> edge_from, Column<int64_t> edge_to> edges,
    Cursor<Column<int64_t> source_node> sources,
    Cursor<Column<int64_t> sink_node> sinks,
    int32_t max_hops | require="max_hops >= 0 && max_hops <= 128") ->
    Column<int64_t> source_node, Column<int64_t> sink_node,
    Column<int64_t> path_node, Column<int32_t> path_step,
    Column<int32_t> path_hops, Column<bool> search_complete
*/
EXTENSION_NOINLINE int32_t tf_metal_graph_paths__cpu_(TableFunctionManager& mgr,
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
                                                      Column<bool>& output_complete);
