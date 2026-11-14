**Native Metal**
HeavyDB, WebServer, and Immerse run natively on this Mac. The SQL backend dispatches supported aggregates and bounded graph traversal to Metal.

This is an experimental backend, not a complete CUDA replacement. Unsupported Metal queries use the existing CPU executor.

Verified host: Apple M5 Pro, 24 GiB RAM, macOS 26.6.2, and Xcode 27.2.
HeavyDB baseline: `c7e0de6df61636af65f9e45aa5f64cf6da5133d0`, version `10.1.0dev`.

**Source Repositories**
Use the `macos-metal` branch in each fork:

| Repository | Fork |
| --- | --- |
| HeavyDB | [Zeerg/omniscidb](https://github.com/Zeerg/omniscidb/tree/macos-metal) |
| Immerse | [Zeerg/immerse](https://github.com/Zeerg/immerse/tree/macos-metal) |
| WebServer | [Zeerg/webserver](https://github.com/Zeerg/webserver/tree/macos-metal) |
| Charting | [Zeerg/heavyai-charting](https://github.com/Zeerg/heavyai-charting/tree/macos-metal) |

Keep the Immerse clone at `immerse-src/` and the WebServer clone at `webserver-src/` inside the HeavyDB checkout.
HeavyDB uses the existing `Zeerg/omniscidb` fork. Its repository name has not changed.
The charting fork preserves the changes also stored in `dev-tools/macos/charting-unbinned.patch`.

**Run**
Run commands from this checkout:

```sh
cd /Users/tom/Projects/heavyai-metal
python3 dev-tools/macos/local-services.py start
python3 dev-tools/macos/local-services.py status
```

Open `http://127.0.0.1:6273`.
The local UI logs in automatically. You do not need to enter a username or password.
`http://localhost:6273` also uses the current browser address for its connection.

| Setting | Value |
| --- | --- |
| Database | `heavyai` |
| Username | `admin` |
| Initial upstream password | `HyperInteractive` |
| Data directory | `build-macos/metal-data` |
| Database console log | `build-macos/heavydb-console.log` |
| WebServer console log | `build-macos/web-console.log` |

The launcher uses two named jobs in the current user's `launchd` session. It does not register login items or initialize data.
The jobs remain independent of the terminal. Run `start` again after logout or reboot.
The HeavyDB job sets a 4,096-file descriptor limit. macOS's default 256-file limit is too small for the combined datasets.
Job definitions are generated under `build-macos/`. They do not change system-wide limits.

Stop only these jobs:

```sh
python3 dev-tools/macos/local-services.py stop
```

The stop command waits for both jobs to exit. It does not remove database files.
Keep this experimental build on loopback. Do not expose its default account to a network.
Automatic login uses `dev-tools/macos/servers.local.json` when that file exists.
Otherwise, it uses `dev-tools/macos/servers.example.json`, which contains the upstream development account.
Keep local credentials in the ignored override file. Database authentication remains enabled.
Do not use this local configuration for a network deployment.

| Service | Loopback port |
| --- | --- |
| Immerse and WebServer | `6273` |
| HeavyDB binary Thrift | `6274` |
| HeavyDB HTTP binary Thrift | `6276` |
| HeavyDB HTTP JSON Thrift | `6278` |
| Calcite planner | `6279` |

**Metal Scope**
| Metal execution | CPU fallback |
| --- | --- |
| One physical table with unencoded integer or Boolean columns | Joins, encoded columns, strings, floating-point and decimal expressions |
| Comparisons, `AND`, `OR`, `NOT`, `IS NULL`, and widening integer casts | Other expressions and functions |
| Ungrouped, non-distinct `COUNT`, `SUM`, `MIN`, `MAX`, and integer `AVG` | Grouped aggregates, distinct aggregates, projections, and other query shapes |

The backend handles multiple fragments, SQL nulls, retained deleted rows, empty results, and checked integer reduction.
It records `Metal SQL executed:` on success and `Metal SQL fallback to CPU:` for unsupported execution.
The logged `gpu_ms` measures GPU command time, not total SQL time.

The launcher uses `--cpu-only --enable-metal`. The first flag disables the CUDA path; the second enables the separate Metal path.
Raster maps that require the CUDA/Vulkan renderer remain unavailable. This build also disables optional integrations listed in the configuration below.

**Graph Mapping**
`tf_metal_graph_paths` computes source-to-sink mappings inside HeavyDB's native Metal backend.
It accepts any directed graph with integer node IDs. It does not require a specific parser or an external scanner.
Graph construction and source/sink selection remain separate from graph traversal.
Tree-sitter syntax containment is not a value-flow graph.

This example uses the Django value graph from [DJANGO_SECURITY.md](DJANGO_SECURITY.md):

```sql
SELECT * FROM TABLE(tf_metal_graph_paths(
  CURSOR(SELECT edge_from, edge_to FROM django_sec_value_edges),
  CURSOR(SELECT node_id FROM django_sec_value_nodes
         WHERE source_kind = 'HTTP request' ORDER BY node_id LIMIT 32),
  CURSOR(SELECT node_id FROM django_sec_value_nodes
         WHERE sink_signal_id IS NOT NULL),
  64
));
```

The first cursor supplies directed edges as two `BIGINT` columns.
The next cursors supply source and sink IDs as one `BIGINT` column each.
The final argument sets the maximum number of edges in a path.
IDs can be sparse or negative. Duplicate source and sink IDs produce no duplicate mappings. NULL IDs are rejected.

| Output | Meaning |
| --- | --- |
| `source_node`, `sink_node` | Reachable source/sink pair |
| `path_node` | Node in one shortest witness path |
| `path_step` | Zero-based position in that path |
| `path_hops` | Number of edges in that path |
| `search_complete` | Whether the source search finished without an unexplored frontier at the hop limit |

Each mapping has one row per path node, including both endpoints.
A source that is also a sink has a zero-edge path.
A source with no reachable selected sink gets one status row. Its sink and path fields are NULL.
An empty source cursor returns no rows.
`search_complete=false` does not invalidate returned paths. It means that more reachable nodes can exist beyond the cutoff.
Completeness applies only to the supplied graph. It does not prove that a security model covers the program.
Sort results explicitly when row order matters.

The SQL table function uses a host wrapper. Host code compacts IDs and formats witnesses from GPU results.
Metal kernels compute reachability, shortest depths, predecessor selection, and cutoff status.
They process sources in batches of 16. No CPU graph traversal fallback exists.
The function requires `--enable-metal` and an available Metal device.
The server records `Metal graph executed:` with GPU command time and device name.

| Limit | Value |
| --- | --- |
| Distinct node IDs | 1,000,000 |
| Input edges | 2,000,000 |
| Source rows and sink rows | 4,096 each |
| Maximum hops | 0 through 128 |
| Estimated work | 1,000,000,000 work items |
| GPU working set | 256 MiB |
| Output path/status rows | 1,000,000 |

The work estimate is `(edges * (max_hops + 1) + nodes) * sources`.
Oversized inputs and results fail explicitly. They do not silently truncate or switch to CPU traversal.
Narrow the cursors or split source IDs into smaller batches when required.

Run these checks against the current native build:

```sh
build-macos/QueryEngine/MetalGraphTest
build-macos/QueryEngine/MetalRuntimeTest
python3 dev-tools/macos/verify-metal-graph.py
```

The SQL check compares 21 graph cases with reference traversal. It also checks concurrency and invalid inputs.
It creates uniquely named test tables and drops only those tables.

**Performance Dashboard**
Open [Metal Graph Performance](http://127.0.0.1:6273/heavyai/dashboard/7?tab=metal-graph-performance).
The native dashboard compares GPU command time with complete SQL round-trip time.
It shows three source workloads, median/minimum/maximum latency, and the benchmark method.
The data contains saved measurements, not live telemetry. Dashboard refresh does not rerun the benchmark.
The native dashboard shell retains a desktop-width layout on narrow screens. Use a desktop browser for the full view.
Each workload has one warmup and nine measured native Metal runs. Source subsets are nested.
Raw samples and the saved dashboard URL are in `build-macos/metal-graph-performance/`.

```sh
python3 dev-tools/macos/build-metal-graph-dashboard.py build
python3 dev-tools/macos/build-metal-graph-dashboard.py verify
node dev-tools/macos/verify-metal-graph-dashboard.cjs
```

The builder creates one benchmark table and one dashboard. It refuses to replace existing data or saved dashboard edits.
It checks that all prior saved dashboards remain unchanged.

**Verify**
Run the SQL comparison before the browser test:

```sh
python3 dev-tools/macos/verify-metal-sql.py \
  --log build-macos/heavydb-console.log \
  > build-macos/sql-verification.log 2>&1
node dev-tools/macos/verify-webapp.cjs \
  > build-macos/webapp-verification.log 2>&1
```

The SQL test replaces `metal_backend_validation`. It imports 100,005 rows and compares ten result sets with SQLite.
It checks filters, nulls, large integers, empty results, fragments, retained deleted rows, and explicit CPU fallback.
The browser test uses normal controls to create a Number chart with 99,911 remaining rows.
It saves and reloads a dashboard, checks the value, and requires new Metal execution logs.
Each browser run creates a new validation dashboard.

If you change the account password, update `dev-tools/macos/servers.local.json` for automatic browser login.
Also set `HEAVYDB_PASSWORD` before running the SQL tests.
Screenshots and the saved dashboard URL are in `build-macos/immerse-dashboard.png` and `build-macos/verified-dashboard-url.txt`.

Run the independent runtime tests:

```sh
cmake -S QueryEngine/Metal -B build-metal-runtime -DCMAKE_BUILD_TYPE=Release
cmake --build build-metal-runtime -j 4
ctest --test-dir build-metal-runtime --output-on-failure
```

Runtime tests include integer overflow and invalid buffer rejection. They do not replace the SQL and browser tests.

**Refresh Checks**
The planner uses a separate plan for each view query. This avoids shared mutable metadata during concurrent refreshes.
Promise-based chart queries preserve errors. A failed refresh clears its pending state and allows another refresh.
Refresh also clears transient chart query errors so failed charts can render again.
Late chart redraws ignore charts removed during navigation.

If the vulnerability data and dashboard manifest are present, run these read-only checks:

```sh
python3 dev-tools/macos/verify-query-concurrency.py
node dev-tools/macos/verify-dashboard-refresh.cjs
node dev-tools/macos/verify-vulnerability-dashboards.cjs --read-only
node dev-tools/macos/verify-line-chart.cjs
```

The concurrency test checks 800 queries with eight workers.
The refresh test injects failures in isolated Chromium and Firefox sessions. It checks error messages and recovery without saving dashboards.
The line chart test checks date inputs, drag selection, clear controls, hover labels, and page navigation in both browsers.
It compares filtered counts with a separate SQL session and does not save dashboards.

**Rebuild**
Stop the local jobs before rebuilding executable files.
The configured build already contains the required dependency paths:

```sh
export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
cmake --build build-macos --target heavydb initheavy heavysql -j 6
go -C webserver-src build -o ../build-macos/bin/heavy_web_server ./cmd/immerse
cd immerse-src
NODE_OPTIONS=--max-old-space-size=6144 npm exec --yes \
  --package=node@24.11.0 --package=npm@11.6.1 -- npm run build:prod
cd ..
python3 dev-tools/macos/local-services.py start
```

To retain existing bundles during a frontend-only rebuild, use:

```sh
cd immerse-src
NODE_ENV=production BABEL_ENV=production LINK_OVERRIDE_CSS=override \
  NODE_OPTIONS=--max-old-space-size=6144 npm exec --yes \
  --package=node@24.11.0 --package=npm@11.6.1 -- npm run webpack -- \
  --bail --config webpack.config.prod.ts --no-devtool \
  --output-filename '[name].[contenthash].js' \
  --output-chunk-filename '[name].[contenthash].js'
cd ..
launchctl kickstart -k "gui/$(id -u)/local.heavyai.metal.web"
```

WebServer reads `index.html` at startup. Restart it after a frontend build, even if the asset files are already updated.
The web-only restart keeps the database running.

The linked fork branches contain the WebServer and Immerse changes.
The saved patches preserve the WebServer bind option, Immerse fixes, and Django security view.
The existing clones are already patched. On fresh upstream clones, apply these patches first:

```sh
git -C webserver-src apply ../dev-tools/macos/webserver-local-host.patch
git -C immerse-src apply ../dev-tools/macos/immerse-selector.patch
git -C immerse-src apply ../dev-tools/macos/immerse-refresh.patch
git -C immerse-src apply ../dev-tools/macos/immerse-line-chart.patch
git -C immerse-src apply ../dev-tools/macos/immerse-django-security.patch
```

For fresh frontend dependencies, skip the obsolete Puppeteer browser download:

```sh
cd immerse-src
PUPPETEER_SKIP_DOWNLOAD=true PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
  npm exec --yes --package=node@24.11.0 --package=npm@11.6.1 -- npm ci
cd ..
git apply --directory=immerse-src/node_modules/@heavyai/charting \
  dev-tools/macos/charting-unbinned.patch
node immerse-src/node_modules/playwright/cli.js install chromium --only-shell
node immerse-src/node_modules/playwright/cli.js install firefox
```

Apply `charting-unbinned.patch` after each `npm ci`. It supports unbinned date ranges and removes an obsolete axis-input pattern.
The app patch supplies render identifiers and hides duplicate native axis labels.

**Django Security**
See [DJANGO_SECURITY.md](DJANGO_SECURITY.md) for the pinned source index, security views, and verification commands.
Review signals are not confirmed vulnerabilities. Candidate call links do not prove runtime data flow.

**Build Inputs**
Host C++ uses AppleClang. Generated bitcode uses LLVM 14 from `/opt/homebrew/opt/llvm@14`.
Arrow and Parquet use the private 18.1.0 build in `build-macos/deps`.
SQLite uses Homebrew 3.54.1, not the older macOS runtime library.
Java uses OpenJDK 21. The Thrift compiler and Java runtime both use version 0.25.0.
The Immerse build uses Node 24.11.0 and npm 11.6.1.

Homebrew dependencies include `geos`, `thrift`, `gdal`, `c-blosc`, `tbb`, `boost`, `librdkafka`, `libarchive`, `cpr`, and `libmd`.
They also include `maven`, `double-conversion`, `h3`, `sqlite`, `openjdk@21`, `cmake`, `go`, and `node`.
LLVM 14 was installed with the compatible Homebrew bottle:

```sh
brew fetch --bottle-tag=arm64_sonoma llvm@14
brew install --force-bottle llvm@14
```

Do not link this C++17 engine to Homebrew Arrow 26. Its headers require newer C++ features.
Do not lower HeavyDB's SQLite version check. The macOS SDK headers report a newer SQLite version than the system runtime provides.

**Private Arrow**
If the Arrow source is absent, fetch the pinned version:

```sh
git clone --depth 1 --branch apache-arrow-18.1.0 \
  https://github.com/apache/arrow.git build-macos/arrow-src
```

Build the private libraries with the existing RapidJSON headers:

```sh
cmake -S build-macos/arrow-src/cpp -B build-macos/arrow-build \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PWD/build-macos/deps" \
  -DCMAKE_PREFIX_PATH=/opt/homebrew -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -DARROW_BUILD_SHARED=ON -DARROW_BUILD_STATIC=OFF \
  -DARROW_DEPENDENCY_USE_SHARED=ON -DARROW_CSV=ON -DARROW_JSON=ON \
  -DARROW_COMPUTE=ON -DARROW_PARQUET=ON -DARROW_FILESYSTEM=ON \
  -DARROW_S3=OFF -DARROW_CUDA=OFF -DARROW_JEMALLOC=OFF \
  -DARROW_WITH_BROTLI=ON -DARROW_WITH_SNAPPY=ON -DARROW_WITH_ZLIB=ON \
  -DARROW_WITH_ZSTD=ON -DARROW_WITH_LZ4=ON -DARROW_WITH_BZ2=ON \
  -DARROW_BUILD_TESTS=OFF -DARROW_BUILD_EXAMPLES=OFF \
  -DRapidJSON_SOURCE=SYSTEM -DRAPIDJSON_INCLUDE_DIR="$PWD/ThirdParty/rapidjson"
cmake --build build-macos/arrow-build -j 6
cmake --install build-macos/arrow-build
```

**Configure HeavyDB**
Use these options for a fresh native configuration:

```sh
cmake -S . -B build-macos -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=/usr/bin/cc -DCMAKE_CXX_COMPILER=/usr/bin/c++ \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_POLICY_DEFAULT_CMP0167=OLD \
  -DCMAKE_PREFIX_PATH="$PWD/build-macos/deps;/opt/homebrew;/opt/homebrew/opt/icu4c@79;/opt/homebrew/opt/libarchive;/opt/homebrew/opt/libxml2;/opt/homebrew/opt/sqlite" \
  -DLLVM_DIR=/opt/homebrew/opt/llvm@14/lib/cmake/llvm \
  -DClang_DIR=/opt/homebrew/opt/llvm@14/lib/cmake/clang \
  -DArrow_LIBRARY="$PWD/build-macos/deps/lib/libarrow.dylib" \
  -DParquet_LIBRARY="$PWD/build-macos/deps/lib/libparquet.dylib" \
  -DSQLite3_LIBRARY=/opt/homebrew/opt/sqlite/lib/libsqlite3.dylib \
  -DSQLite3_INCLUDE_DIR=/opt/homebrew/opt/sqlite/include \
  -DTHRIFT_MVN_VERSION=0.25.0 -DPREFER_STATIC_LIBS=OFF \
  -DENABLE_METAL=ON -DENABLE_CUDA=OFF -DENABLE_RENDERING=OFF \
  -DENABLE_TESTS=OFF -DENABLE_WARNINGS_AS_ERRORS=OFF \
  -DENABLE_AWS_S3=OFF -DENABLE_PDAL=OFF -DENABLE_POINT_CLOUD_TFS=OFF \
  -DENABLE_FSI_ODBC=OFF -DENABLE_SAML=OFF -DENABLE_LDAP=OFF \
  -DENABLE_ML_MLPACK_TFS=OFF -DENABLE_ML_ONEDAL_TFS=OFF -DENABLE_TORCH_TFS=OFF \
  -DENABLE_RF_PROP_TFS=OFF -DENABLE_GFX_TFS=OFF \
  -DENABLE_OMNIVERSE_CONNECTOR=OFF -DENABLE_RUNTIME_LIBS=OFF
```

For a new data directory only, initialize the catalog before starting services:

```sh
mkdir -p build-macos/metal-data
JAVA_TOOL_OPTIONS=-Dheavyai.listen.address=127.0.0.1 \
  build-macos/bin/initheavy --data "$PWD/build-macos/metal-data" --skip-geo
```

Do not use `--force` on an existing data directory.
The launcher supplies the native GEOS library path and limits CPU buffers to 4 GiB, CPU threads to eight, and executors to two.
