#!/usr/bin/env python3
"""Compare real HeavyDB SQL results with SQLite and require Metal execution logs."""

import argparse
import csv
import math
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, default=root / "build-macos/bin/heavysql")
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default="6274")
    parser.add_argument("--database", default="heavyai")
    args = parser.parse_args()
    password = os.environ.get("HEAVYDB_PASSWORD", "HyperInteractive")
    command = [str(args.client), "--quiet", "--no-header", "--delimiter", "|",
               "--server", args.host, "--port", args.port, "--db", args.database,
               "--user", "admin", "--passwd", password]

    def sql(query):
        result = subprocess.run(command, input=query + ";\n", text=True,
                                capture_output=True, timeout=120)
        if result.returncode or "Exception" in result.stderr or "Error" in result.stderr:
            raise RuntimeError(f"HeavyDB query failed: {query}\n{result.stderr}")
        return [line.split("|") for line in result.stdout.strip().splitlines() if line.strip()]

    table = "metal_backend_validation"
    log_offset = args.log.stat().st_size
    reference = sqlite3.connect(":memory:")
    reference.execute(f"CREATE TABLE {table}(value64 BIGINT, small_num SMALLINT, "
                      "int_num INT, flag BOOLEAN)")
    rows = []
    for index in range(100003):
        value = None if index % 97 == 0 else index % 1000 - 500
        small = None if index % 37 == 0 else index % 600 - 300
        integer = None if index % 17 == 0 else index % 200 - 100
        flag = None if index % 19 == 0 else int(index % 3 == 0)
        rows.append((value, small, integer, flag))
    rows.extend([(9007199254740993, 1, 1, 1), (-9007199254740993, -1, -1, 0)])
    reference.executemany(f"INSERT INTO {table} VALUES (?,?,?,?)", rows)

    fixture = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", newline="", suffix=".csv",
                                         prefix="metal-validation-", dir=root / "build-macos",
                                         delete=False) as stream:
            fixture = Path(stream.name)
            writer = csv.writer(stream)
            writer.writerow(["value64", "small_num", "int_num", "flag"])
            for row in rows:
                writer.writerow(["NULL" if value is None else value for value in row])
        sql(f"DROP TABLE IF EXISTS {table}")
        sql(f"CREATE TABLE {table}(value64 BIGINT, small_num SMALLINT, int_num INT, "
            "flag BOOLEAN) WITH (FRAGMENT_SIZE=32000)")
        sql(f"COPY {table} FROM '{str(fixture).replace(chr(39), chr(39) * 2)}' "
            "WITH (HEADER='true', NULLS='NULL')")

        queries = [
            f"SELECT COUNT(*), COUNT(value64), SUM(value64), MIN(value64), MAX(value64), "
            f"AVG(value64) FROM {table}",
            f"SELECT COUNT(*), SUM(value64), MIN(value64), MAX(value64), AVG(value64) "
            f"FROM {table} WHERE value64>=-100 AND value64<200",
            f"SELECT COUNT(*), SUM(int_num), MIN(small_num), MAX(small_num) FROM {table} "
            "WHERE (value64 IS NULL OR value64=2) AND NOT (flag=false)",
            f"SELECT COUNT(*), SUM(value64) FROM {table} WHERE "
            "(value64 < -100 OR small_num IS NULL) AND (flag OR int_num>=0)",
            f"SELECT COUNT(*), SUM(small_num) FROM {table} WHERE NOT (flag AND value64>5)",
            f"SELECT COUNT(*), SUM(value64), AVG(value64), MIN(value64), MAX(value64) "
            f"FROM {table} WHERE value64>9223372036854775806",
            f"SELECT COUNT(*), SUM(value64) FROM {table} WHERE value64=9007199254740993",
            f"SELECT flag, COUNT(*) FROM {table} WHERE flag IS NOT NULL "
            "GROUP BY flag ORDER BY flag",
        ]

        def compare(query):
            expected = reference.execute(query).fetchall()
            actual = sql(query)
            if len(actual) != len(expected):
                raise AssertionError(f"Row count mismatch: {query}\n{actual}\n{expected}")
            for actual_row, expected_row in zip(actual, expected):
                if len(actual_row) != len(expected_row):
                    raise AssertionError(f"Column count mismatch: {query}")
                for actual_value, expected_value in zip(actual_row, expected_row):
                    actual_value = actual_value.strip()
                    if expected_value is None:
                        matches = actual_value.upper() == "NULL"
                    elif isinstance(expected_value, float):
                        matches = math.isclose(float(actual_value), expected_value,
                                               rel_tol=2e-12, abs_tol=1e-8)
                    elif isinstance(expected_value, int):
                        if actual_value.lower() in ("true", "false"):
                            actual_value = "1" if actual_value.lower() == "true" else "0"
                        matches = int(actual_value) == expected_value
                    else:
                        matches = actual_value == expected_value
                    if not matches:
                        raise AssertionError(f"Result mismatch: {query}\n"
                                             f"actual={actual_row}, expected={expected_row}")
            print("PASS:", query)

        for query in queries:
            compare(query)
        deletion = f"DELETE FROM {table} WHERE int_num=-99 AND value64=-499"
        sql(deletion)
        reference.execute(deletion)
        compare(queries[0])
        compare(queries[1])
        with args.log.open("rb") as stream:
            stream.seek(log_offset)
            evidence = stream.read().decode("utf-8", errors="replace")
        if "Metal SQL executed:" not in evidence:
            raise AssertionError("No real Metal SQL execution was recorded")
        if "Metal SQL fallback to CPU:" not in evidence:
            raise AssertionError("The unsupported query did not record CPU fallback")
        if evidence.count(f"rows={len(rows)} aggregates=6") < 2:
            raise AssertionError("The deletion test did not retain physical rows for Metal filtering")
        print(f"PASS: {len(queries) + 2} SQL comparisons, multiple fragments, deleted rows, "
              "Metal execution and CPU fallback evidence")
    finally:
        if fixture is not None:
            fixture.unlink(missing_ok=True)
        reference.close()


if __name__ == "__main__":
    main()
