#!/usr/bin/env python3
"""Check concurrent view queries against independent sequential results."""

from concurrent.futures import ThreadPoolExecutor
from vulnerability_db import HeavyDB


def main():
    queries = [
        "SELECT COUNT(*) FROM vuln_priority WHERE primary_vendor = 'microsoft'",
        "SELECT SUM(is_kev) FROM vuln_priority WHERE primary_vendor = 'microsoft'",
        "SELECT COUNT(*) FROM vuln_published WHERE cvss_band = 'Critical'",
        "SELECT COUNT(*) FROM vuln_published WHERE primary_vendor = 'microsoft'",
    ]
    with HeavyDB() as database:
        expected = [database.sql(query) for query in queries]

        def check(index):
            query_index = index % len(queries)
            try:
                actual = database.sql(queries[query_index])
                if actual != expected[query_index]:
                    return f"Query {query_index}: {actual!r} != {expected[query_index]!r}"
            except Exception as error:
                return f"Query {query_index}: {error}"
            return None

        with ThreadPoolExecutor(max_workers=8) as executor:
            failures = [error for error in executor.map(check, range(800)) if error]
        if failures:
            raise AssertionError(f"{len(failures)} concurrent failures: {failures[:8]}")
        print("PASS: 800 concurrent view queries match their sequential results")


if __name__ == "__main__":
    main()
