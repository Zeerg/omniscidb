/*
 * SPDX-License-Identifier: Apache-2.0
 */
#include "MetalExecutor.h"

#include "Catalog/Catalog.h"
#include "Catalog/SysCatalog.h"
#include "MetalRuntime.h"
#include "QueryEngine/ColumnFetcher.h"
#include "QueryEngine/ErrorHandling.h"
#include "QueryEngine/Execute.h"
#include "QueryEngine/ResultSetStorage.h"

#include <limits>
#include <sstream>
#include <stdexcept>

bool g_enable_metal{false};

namespace {

struct UnsupportedMetalQuery : std::runtime_error {
  using std::runtime_error::runtime_error;
};

struct Expression {
  std::string value;
  std::string valid;
  bool boolean;
};

std::string integerLiteral(int64_t value) {
  if (value == INT64_MIN) {
    return "(-9223372036854775807L-1L)";
  }
  return std::to_string(value) + "L";
}

class MetalCompiler {
 public:
  heavyai::metal::ScanPlan plan;
  std::vector<std::shared_ptr<Analyzer::ColumnVar>> columns;
  shared::TableKey table;

  explicit MetalCompiler(const shared::TableKey& table_key) : table(table_key) {
    plan.predicate = "true";
  }

  Expression expression(const Analyzer::Expr* expr) {
    if (!expr ||
        (!expr->get_type_info().is_integer() && !expr->get_type_info().is_boolean())) {
      throw UnsupportedMetalQuery("only integer and boolean expressions are supported");
    }
    if (auto column = dynamic_cast<const Analyzer::ColumnVar*>(expr)) {
      return columnExpression(*column);
    }
    if (auto constant = dynamic_cast<const Analyzer::Constant*>(expr)) {
      int64_t value = 0;
      const auto datum = constant->get_constval();
      if (!constant->get_is_null()) {
        switch (constant->get_type_info().get_type()) {
          case kBOOLEAN:
            value = datum.boolval;
            break;
          case kTINYINT:
            value = datum.tinyintval;
            break;
          case kSMALLINT:
            value = datum.smallintval;
            break;
          case kINT:
            value = datum.intval;
            break;
          case kBIGINT:
            value = datum.bigintval;
            break;
          default:
            throw UnsupportedMetalQuery("unsupported constant type");
        }
      }
      return {integerLiteral(value),
              constant->get_is_null() ? "false" : "true",
              constant->get_type_info().is_boolean()};
    }
    if (auto unary = dynamic_cast<const Analyzer::UOper*>(expr)) {
      auto operand = expression(unary->get_operand());
      switch (unary->get_optype()) {
        case kISNULL:
          return {"!(" + operand.valid + ")", "true", true};
        case kNOT:
          if (operand.boolean) {
            return {"!(" + operand.value + ")", operand.valid, true};
          }
          break;
        case kCAST:
          if (expr->get_type_info().is_integer() &&
              unary->get_operand()->get_type_info().is_integer() &&
              expr->get_type_info().get_size() >=
                  unary->get_operand()->get_type_info().get_size()) {
            return operand;
          }
          break;
        default:
          break;
      }
      throw UnsupportedMetalQuery("unsupported unary operation or narrowing cast");
    }
    if (auto binary = dynamic_cast<const Analyzer::BinOper*>(expr)) {
      if (binary->get_qualifier() != kONE) {
        throw UnsupportedMetalQuery("ANY/ALL comparisons are not supported");
      }
      const auto left = expression(binary->get_left_operand());
      const auto right = expression(binary->get_right_operand());
      const auto left_true = "(" + left.valid + " && " + left.value + ")";
      const auto right_true = "(" + right.valid + " && " + right.value + ")";
      if (binary->get_optype() == kAND && left.boolean && right.boolean) {
        return {"(" + left_true + " && " + right_true + ")",
                "((" + left.valid + " && !(" + left.value + ")) || (" + right.valid +
                    " && !(" + right.value + ")) || (" + left.valid + " && " +
                    right.valid + "))",
                true};
      }
      if (binary->get_optype() == kOR && left.boolean && right.boolean) {
        return {"(" + left_true + " || " + right_true + ")",
                "(" + left_true + " || " + right_true + " || (" + left.valid + " && " +
                    right.valid + "))",
                true};
      }
      const char* operation = nullptr;
      switch (binary->get_optype()) {
        case kEQ:
          operation = "==";
          break;
        case kNE:
          operation = "!=";
          break;
        case kLT:
          operation = "<";
          break;
        case kLE:
          operation = "<=";
          break;
        case kGT:
          operation = ">";
          break;
        case kGE:
          operation = ">=";
          break;
        default:
          throw UnsupportedMetalQuery("unsupported binary operation");
      }
      return {"(" + left.value + operation + right.value + ")",
              "(" + left.valid + " && " + right.valid + ")",
              true};
    }
    throw UnsupportedMetalQuery("unsupported expression node");
  }

  void predicate(const Analyzer::Expr* expr) {
    const auto code = expression(expr);
    if (!code.boolean) {
      throw UnsupportedMetalQuery("the filter is not boolean");
    }
    plan.predicate += " && (" + code.valid + " && " + code.value + ")";
  }

 private:
  Expression columnExpression(const Analyzer::ColumnVar& column) {
    if (column.getTableKey() != table || column.get_rte_idx() != 0) {
      throw UnsupportedMetalQuery("only one physical input table is supported");
    }
    const auto descriptor =
        Catalog_Namespace::get_metadata_for_column(column.getColumnKey());
    if (!descriptor || descriptor->isVirtualCol ||
        descriptor->columnType.get_compression() != kENCODING_NONE) {
      throw UnsupportedMetalQuery("virtual or encoded columns are not supported");
    }
    const auto& type = descriptor->columnType;
    if (!type.is_integer() && !type.is_boolean()) {
      throw UnsupportedMetalQuery("unsupported physical column type");
    }
    size_t index = 0;
    for (; index < columns.size(); ++index) {
      if (columns[index]->getColumnKey() == column.getColumnKey()) {
        break;
      }
    }
    if (index == columns.size()) {
      if (index == 28) {
        throw UnsupportedMetalQuery("too many Metal input buffers");
      }
      columns.push_back(std::make_shared<Analyzer::ColumnVar>(
          type, column.getColumnKey(), column.get_rte_idx()));
      using heavyai::metal::IntegerType;
      switch (type.get_size()) {
        case 1:
          plan.columns.push_back(IntegerType::Int8);
          break;
        case 2:
          plan.columns.push_back(IntegerType::Int16);
          break;
        case 4:
          plan.columns.push_back(IntegerType::Int32);
          break;
        case 8:
          plan.columns.push_back(IntegerType::Int64);
          break;
        default:
          throw UnsupportedMetalQuery("unsupported integer width");
      }
    }
    const auto value = "long(c" + std::to_string(index) + "[row])";
    return {value,
            type.get_notnull()
                ? "true"
                : "(" + value + "!=" + integerLiteral(inline_int_null_val(type)) + ")",
            type.is_boolean()};
  }
};

}  // namespace

ResultSetPtr tryExecuteMetal(Executor* executor,
                             const RelAlgExecutionUnit& unit,
                             const std::vector<InputTableInfo>& tables,
                             ColumnCacheMap& column_cache,
                             bool filter_deleted) {
  if (!g_enable_metal) {
    return nullptr;
  }
  try {
    if (!heavyai::metal::available()) {
      throw UnsupportedMetalQuery("no Metal device is available");
    }
    if (unit.query_hint.cpu_mode || unit.input_descs.size() != 1 || tables.size() != 1 ||
        unit.input_descs.front().getTableKey().table_id <= 0 ||
        !unit.groupby_exprs.empty() || !unit.join_quals.empty() || unit.estimator ||
        unit.union_all.has_value() || unit.scan_limit || unit.target_exprs.empty()) {
      throw UnsupportedMetalQuery("query shape requires the CPU executor");
    }
    MetalCompiler compiler(unit.input_descs.front().getTableKey());
    for (const auto& qual : unit.simple_quals) {
      compiler.predicate(qual.get());
    }
    for (const auto& qual : unit.quals) {
      compiler.predicate(qual.get());
    }
    if (filter_deleted) {
      const auto catalog =
          Catalog_Namespace::SysCatalog::instance().getCatalog(compiler.table.db_id);
      const auto table = catalog->getMetadataForTable(compiler.table.table_id);
      if (const auto deleted = catalog->getDeletedColumnIfRowsDeleted(table)) {
        Analyzer::ColumnVar deleted_column(
            deleted->columnType, {compiler.table, deleted->columnId}, 0);
        const auto code = compiler.expression(&deleted_column);
        compiler.plan.predicate += " && (" + code.value + "==0)";
      }
    }

    std::vector<SQLTypeInfo> output_types;
    for (auto target : unit.target_exprs) {
      auto aggregate = dynamic_cast<const Analyzer::AggExpr*>(target);
      if (!aggregate || aggregate->get_is_distinct()) {
        throw UnsupportedMetalQuery("only non-distinct aggregate targets are supported");
      }
      using heavyai::metal::AggregateKind;
      AggregateKind kind;
      switch (aggregate->get_aggtype()) {
        case kCOUNT:
          kind = AggregateKind::Count;
          break;
        case kSUM:
          kind = AggregateKind::Sum;
          break;
        case kMIN:
          kind = AggregateKind::Min;
          break;
        case kMAX:
          kind = AggregateKind::Max;
          break;
        case kAVG:
          kind = AggregateKind::Avg;
          break;
        default:
          throw UnsupportedMetalQuery("unsupported aggregate");
      }
      const auto& output_type = aggregate->get_type_info();
      if ((kind == AggregateKind::Avg && output_type.get_type() != kDOUBLE) ||
          (kind != AggregateKind::Avg && !output_type.is_integer())) {
        throw UnsupportedMetalQuery("unsupported aggregate result type");
      }
      const auto argument = aggregate->get_arg()
                                ? compiler.expression(aggregate->get_arg())
                                : Expression{"0L", "true", false};
      if (!aggregate->get_arg() && kind != AggregateKind::Count) {
        throw UnsupportedMetalQuery("aggregate argument is missing");
      }
      compiler.plan.aggregates.push_back({kind, argument.value, argument.valid});
      output_types.push_back(output_type);
    }

    std::vector<heavyai::metal::Partial> totals;
    double gpu_time_ms = 0;
    size_t rows_scanned = 0;
    for (const auto& fragment : tables.front().info.fragments) {
      if (executor->checkNonKernelTimeInterrupted()) {
        throw QueryExecutionError(ErrorCode::INTERRUPTED);
      }
      if (fragment.isEmptyPhysicalFragment() || fragment.getNumTuples() == 0) {
        continue;
      }
      std::vector<std::shared_ptr<Chunk_NS::Chunk>> owners;
      std::vector<heavyai::metal::ColumnBuffer> buffers;
      for (const auto& column : compiler.columns) {
        const auto [data, rows] =
            ColumnFetcher::getOneColumnFragment(executor,
                                                *column,
                                                fragment,
                                                Data_Namespace::CPU_LEVEL,
                                                0,
                                                nullptr,
                                                0,
                                                owners,
                                                column_cache);
        if (!data || rows != fragment.getNumTuples()) {
          throw std::runtime_error("Metal input fragment has an unexpected row count");
        }
        buffers.push_back({data, rows * size_t(column->get_type_info().get_size())});
      }
      const auto scan =
          heavyai::metal::executeScan(compiler.plan, buffers, fragment.getNumTuples());
      if (executor->checkNonKernelTimeInterrupted()) {
        throw QueryExecutionError(ErrorCode::INTERRUPTED);
      }
      heavyai::metal::mergePartials(totals, scan.partials, compiler.plan.aggregates);
      gpu_time_ms += scan.gpu_time_ms;
      rows_scanned += fragment.getNumTuples();
    }
    if (totals.empty()) {
      totals.resize(output_types.size());
    }

    QueryMemoryDescriptor memory(executor, 1, QueryDescriptionType::Projection);
    std::vector<TargetInfo> targets;
    for (const auto& type : output_types) {
      targets.push_back({false, kSAMPLE, type, type, true, false, false});
      memory.addColSlotInfo({std::make_tuple(type.get_size(), 8)});
    }
    auto result = std::make_shared<ResultSet>(
        targets, ExecutorDeviceType::CPU, memory, executor->getRowSetMemoryOwner(), 0, 0);
    auto output =
        reinterpret_cast<int64_t*>(result->allocateStorage()->getUnderlyingBuffer());
    for (size_t i = 0; i < totals.size(); ++i) {
      const auto& value = totals[i];
      const auto kind = compiler.plan.aggregates[i].kind;
      using heavyai::metal::AggregateKind;
      if (kind == AggregateKind::Avg) {
        reinterpret_cast<double*>(output)[i] =
            value.count ? double(value.value) / double(value.count)
                        : inline_fp_null_value<double>();
      } else if (kind != AggregateKind::Count && value.count == 0) {
        output[i] = inline_int_null_val(output_types[i]);
      } else {
        const int64_t scalar =
            kind == AggregateKind::Count ? int64_t(value.count) : value.value;
        const auto bits = output_types[i].get_logical_size() * 8;
        const auto maximum = bits == 64 ? INT64_MAX : (int64_t(1) << (bits - 1)) - 1;
        if (scalar > maximum || scalar <= inline_int_null_val(output_types[i])) {
          throw std::overflow_error("Metal aggregate result exceeds its SQL type");
        }
        output[i] = scalar;
      }
    }
    LOG(INFO) << "Metal SQL executed: device=" << heavyai::metal::deviceName()
              << " rows=" << rows_scanned << " aggregates=" << targets.size()
              << " gpu_ms=" << gpu_time_ms;
    return result;
  } catch (const QueryExecutionError&) {
    throw;
  } catch (const std::exception& error) {
    LOG(INFO) << "Metal SQL fallback to CPU: " << error.what();
    return nullptr;
  }
}
