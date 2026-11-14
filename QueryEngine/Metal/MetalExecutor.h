/*
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include "QueryEngine/ColumnarResults.h"
#include "QueryEngine/InputMetadata.h"

extern bool g_enable_metal;

ResultSetPtr tryExecuteMetal(Executor* executor,
                             const RelAlgExecutionUnit& unit,
                             const std::vector<InputTableInfo>& tables,
                             ColumnCacheMap& column_cache,
                             bool filter_deleted);
