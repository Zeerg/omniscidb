#!/usr/bin/env python3
"""Compare real HeavyDB Metal SQL with a reference traversal. Drop only owned test tables."""

from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
import json
import os
import random

from vulnerability_db import HeavyDB


def reference(edges, sources, sinks, limit):
    adjacent = defaultdict(set)
    for start, end in edges:
        adjacent[start].add(end)
    distances, complete = {}, {}
    for source in set(sources):
        depth, queue = {source: 0}, deque([source])
        while queue:
            node = queue.popleft()
            if depth[node] == limit:
                continue
            for target in adjacent[node]:
                if target not in depth:
                    depth[target] = depth[node] + 1
                    queue.append(target)
        complete[source] = not any(depth[node] == limit and target not in depth
                                   for node in depth for target in adjacent[node])
        for sink in set(sinks):
            if sink in depth:
                distances[source, sink] = depth[sink]
    return distances, complete


def check(rows, edges, sources, sinks, limit):
    expected, complete = reference(edges, sources, sinks, limit)
    groups, seen_sources = defaultdict(list), set()
    for source, sink, node, step, hops, finished in rows:
        seen_sources.add(source)
        assert bool(finished) == complete[source], (source, finished, complete)
        if sink is None:
            assert [node, step, hops] == [None, None, None]
            assert not any(key[0] == source for key in expected)
        else:
            groups[source, sink].append((step, node, hops))
    assert seen_sources == set(sources), (seen_sources, sources)
    assert set(groups) == set(expected), (set(groups), set(expected))
    edges = set(edges)
    for key, values in groups.items():
        values.sort()
        assert [row[0] for row in values] == list(range(expected[key] + 1))
        nodes = [row[1] for row in values]
        assert nodes[0] == key[0] and nodes[-1] == key[1]
        assert all(row[2] == expected[key] for row in values)
        assert all(pair in edges for pair in zip(nodes, nodes[1:]))


def main():
    generator = random.Random(57)
    cases = [
        ([(1, 2), (2, 3), (3, 4)], [1, 4, 9], [1, 3, 4, 9], limit)
        for limit in (0, 1, 2, 4)
    ]
    cases += [
        ([(1, 2), (1, 3), (2, 4), (3, 4), (4, 1), (1, 2)], [1, 1, 4], [1, 4, 8, 8], 8),
        ([(2**53 + 17, -91), (-91, 2**62 + 7)], [2**53 + 17], [2**62 + 7, -91], 8),
        ([], [7, 8], [7, 8, 9], 3),
        ([(1, 2)], [1], [], 3),
        ([(1, 2)], [], [2], 3),
    ]
    for unused in range(12):
        cases.append(([(generator.randrange(45), generator.randrange(45)) for edge in range(130)],
                      list(range(19)), list(range(50)), generator.randrange(9)))
    prefix = f"metal_graph_check_{os.getpid()}"
    tables = [prefix + suffix for suffix in ("_edges", "_sources", "_sinks")]
    created = []
    report = []
    with HeavyDB() as db:
        assert "tf_metal_graph_paths" in db.call("get_table_function_names", db.session)
        try:
            for table, definition in zip(tables, ("case_id INT,src BIGINT,dst BIGINT", "case_id INT,node BIGINT", "case_id INT,node BIGINT")):
                db.sql(f"CREATE TABLE {table} ({definition})")
                created.append(table)
            for index, (edges, sources, sinks, limit) in enumerate(cases):
                for table, values in zip(tables, ([f"({index},{a},{b})" for a, b in edges],
                                                [f"({index},{node})" for node in sources],
                                                [f"({index},{node})" for node in sinks])):
                    if values:
                        db.sql(f"INSERT INTO {table} VALUES " + ",".join(values))

            def statement(index, limit):
                return ("SELECT * FROM TABLE(tf_metal_graph_paths("
                        f"CURSOR(SELECT src,dst FROM {tables[0]} WHERE case_id={index}),"
                        f"CURSOR(SELECT node FROM {tables[1]} WHERE case_id={index}),"
                        f"CURSOR(SELECT node FROM {tables[2]} WHERE case_id={index}),{limit}))")

            for index, (edges, sources, sinks, limit) in enumerate(cases):
                rows = db.sql(statement(index, limit))
                check(rows, edges, sources, sinks, limit)
                report.append(dict(case=index, rows=len(rows), max_hops=limit))
                print(f"PASS: SQL graph case {index}, {len(rows)} witness/status rows", flush=True)

            def concurrent(index):
                with HeavyDB() as session:
                    rows = session.sql(statement(index, cases[index][3]))
                    check(rows, *cases[index])
            with ThreadPoolExecutor(max_workers=2) as pool:
                list(pool.map(concurrent, (4, 10)))
            for invalid in (-1, 129):
                try:
                    db.sql(statement(0, invalid))
                except RuntimeError as error:
                    assert "max_hops" in str(error)
                else:
                    raise AssertionError("Invalid hop limit was accepted")
            db.sql(f"INSERT INTO {tables[1]} VALUES (99,NULL)")
            db.sql(f"INSERT INTO {tables[0]} VALUES (99,1,2)")
            db.sql(f"INSERT INTO {tables[2]} VALUES (99,2)")
            try:
                db.sql(statement(99, 4))
            except RuntimeError as error:
                assert "NULL" in str(error)
            else:
                raise AssertionError("NULL source was accepted")
        finally:
            for table in reversed(created):
                db.sql(f"DROP TABLE {table}")
    print("PASS: native HeavyDB SQL, reference equivalence, witness edges, shortest distances, cutoff status, sparse 64-bit IDs, empty inputs, concurrency, and rejected inputs")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
