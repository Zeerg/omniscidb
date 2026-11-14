# Django Security Atlas

The atlas indexes Django source in HeavyDB and adds a protected investigation view to Immerse.
It does not execute or import Django.

## Open

- Source investigation: http://127.0.0.1:6273/heavyai/security-code
- Native dashboard: http://127.0.0.1:6273/heavyai/dashboard/6?tab=django-security-atlas
- Use the Security link in the Immerse navigation panel.

The source view opens in Sources and sinks mode. Select a mapping to inspect source, value steps, sink, and nearby control references.
Trace steps select exact source lines. The URL preserves the mapping, file, scope, line, and analysis mode.
The Overview dashboard link returns to the native dashboard. Its source link returns to this investigation view.
All signals mode provides category, evidence-role, package, and scope filters.
Select a signal to inspect its explanation, source, syntax containment, and call candidates.
The code cross-section uses source spans and nesting depth. Its dimensions are not risk scores.
Use Zoom to scope to inspect a selected definition.
Call links navigate between candidate definitions. They do not establish runtime paths.
The URL preserves the selected file, scope, and line. GitHub links use the pinned commit.

## Source

- Repository: https://github.com/django/django
- Release: 6.1.3
- Commit: `f16e25dcb9fe55734ba4ea2b00ac34405b7df74a`
- Parser: Tree-sitter 0.25.2 with tree-sitter-python 0.25.0
- Semantic extraction: Python 3.14 `ast`, without code execution
- Scope: Python files under `django/`

Repository `tests/` and `docs/` directories are excluded. Framework utilities under `django/test/` remain included.
The original BSD license remains in the source checkout.

## Evidence

Review signals are not confirmed vulnerabilities. The rules identify sensitive operations, input references, trust overrides, and protective controls.
Categories include SQL, HTML, process execution, deserialization, filesystem access, URL trust, authentication, request trust, cryptography, and dynamic code.
SQL execution matches include method-name heuristics. The receiver may not be a database cursor.
Protective API references do not prove complete protection.

The base signal index does not establish taint flow, exploitability, application routes, deployment exposure, or complete security coverage.
Call resolution is limited to lexical names, import references, and same-class receiver candidates.
Dynamic and unresolved targets remain explicit. Resolved call names are still candidates, not observed execution.

HeavyDB stores six separate tables:

| Table | Content |
| --- | --- |
| `django_sec_files` | Source paths, hashes, complete source, and file counts |
| `django_sec_nodes` | Named concrete syntax nodes, parents, types, and byte spans |
| `django_sec_symbols` | Module, class, and function scopes |
| `django_sec_edges` | Syntax containment, import references, call candidates, and unresolved calls |
| `django_sec_signals` | Rule evidence, source locations, roles, and limitations |
| `django_sec_snapshot` | Pinned release, commit, parser version, counts, and analysis limits |

HeavyDB filters and summarizes the index. The browser follows bounded, one-hop call candidates.
The separate native Metal graph operator computes bounded reachability over modeled value dependencies.
The source view uses the existing authenticated Immerse connection. It adds no filesystem or unauthenticated source endpoint.
Source code renders as text, not HTML. Query values are quoted, identifiers are validated, and result sizes are bounded.

## Native Mappings

The parser builds value nodes and directed def-use/value edges. These nodes reference the existing Tree-sitter syntax IDs.
Graph extraction does not propagate source labels or compute source/sink pairs.
The loader calls `tf_metal_graph_paths` through `INSERT INTO ... SELECT` inside HeavyDB.
Metal kernels compute reachability and witness predecessors. Python attaches source metadata to the returned witnesses for the UI.
There is no external scanner dependency or CPU traversal fallback in this mapping path.
See [MACOS_METAL.md](MACOS_METAL.md#graph-mapping) for the SQL contract, output fields, execution boundary, and resource limits.

| Additional table | Content |
| --- | --- |
| `django_sec_value_nodes` | Local value nodes, syntax references, source candidates, and sensitive sink arguments |
| `django_sec_value_edges` | Directed value dependencies and explicit opaque-return assumptions |
| `django_sec_graph_paths` | Native operator witness rows and per-source cutoff status |
| `django_sec_flows` | Source metadata and display traces for native mappings |
| `django_sec_flow_snapshot` | Model version, value-edge content hash, counts, and limits |

The initial graph has 17,397 value nodes, 19,200 edges, 616 source candidates, and 383 sink arguments.
The native operator produces 379 mappings: 8 HTTP request-reference paths and 371 caller-parameter paths.
No source search reaches the 64-edge cutoff in this snapshot. Thirteen sink signals have no modeled argument node.
These counts describe this model and pinned source. They are not vulnerability counts.

Source candidates include request-data references and caller parameters other than `self` and `cls`.
Caller parameters do not establish attacker control. Request references still need object and deployment review.
Sinks include SQL text, HTML trust overrides, process arguments, serialized input, dynamic code, filesystem paths, and redirect targets.
SQL sink nodes exclude bound parameter values. Existing signal confidence and name-resolution limits still apply.

The initial model covers local function scopes with modeled sinks. It does not connect function arguments to callee parameters.
Opaque call returns propagate value influence by assumption. These edges are labeled `assumed call return`.
Comprehensions, generators, and lambdas have no modeled value propagation.
Heap aliases, complete heap updates, and branch feasibility are not proven. Unsupported constructs remain counted in `metal-graph-manifest.json`.
Control references are not proven guards. Missing mappings do not prove safety.

## Reproduce

Run these commands from the HeavyDB project root.
If the source checkout already exists, do not clone over it. The indexer rejects a different commit or a dirty checkout.

```sh
git clone --depth 1 --branch 6.1.3 https://github.com/django/django.git build-macos/django-source
uv venv --python /opt/homebrew/bin/python3.14 build-macos/django-security/venv
uv pip install --python build-macos/django-security/venv/bin/python -r dev-tools/macos/django-security-requirements.txt
build-macos/django-security/venv/bin/python dev-tools/macos/django_security.py index
build-macos/django-security/venv/bin/python dev-tools/macos/django_security.py load
build-macos/django-security/venv/bin/python dev-tools/macos/django_security.py verify
build-macos/django-security/venv/bin/python dev-tools/macos/django_metal_graph.py facts
build-macos/django-security/venv/bin/python dev-tools/macos/django_metal_graph.py load
build-macos/django-security/venv/bin/python dev-tools/macos/django_metal_graph.py verify
python3 dev-tools/macos/build-django-security-dashboard.py
```

The loader uses a nonquoted delimiter format to preserve source quotes exactly.
It checks row counts, IDs, source hashes, references, rule totals, and complete evidence rows.
Generated data and reports are in `build-macos/django-security/`.

The loader does not append to existing tables. It checks existing snapshots instead.
The explicit `reload` action replaces only the six atlas tables after checking their snapshot commit.
It refuses partial datasets and snapshots with another commit.
Do not use `reload` to switch releases.
The dashboard builder creates a new dashboard once. It refuses to replace saved edits.
Existing vulnerability tables and dashboards remain separate.
The graph loader creates only the five additional tables. It refuses to append or replace existing graph tables.
Do not reload the base index while retaining graph tables from a different index.

## Verify

```sh
build-macos/django-security/venv/bin/python -m unittest discover -s dev-tools/macos -p 'test_django_*.py' -v
build-macos/django-security/venv/bin/python dev-tools/macos/django_security.py verify
build-macos/django-security/venv/bin/python dev-tools/macos/django_metal_graph.py verify
python3 dev-tools/macos/verify-metal-graph.py
node dev-tools/macos/verify-django-security.cjs
```

The graph verifier compares stored native paths with reference traversal. It checks exact rows, shortest paths, cutoff status, syntax references, and trace metadata.
The browser test checks mappings, source kinds, trace navigation, reciprocal links, native KPIs, signal filters, exact source, candidate navigation, and mobile layout.
It uses Chromium and Firefox without saving dashboards or injecting application state.

## Frontend Patch

The existing clone already contains the view. For a fresh clone, apply the earlier Immerse patches from `MACOS_METAL.md` first.
Then apply the atlas patch:

```sh
git -C immerse-src apply ../dev-tools/macos/immerse-django-security.patch
```

Use the frontend-only build and web-only restart commands in `MACOS_METAL.md`.
Frontend-only changes do not need a database restart. Native operator changes require a HeavyDB rebuild and restart.
