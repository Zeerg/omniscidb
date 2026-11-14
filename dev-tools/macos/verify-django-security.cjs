#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const root = path.resolve(__dirname, "../..");
const { chromium, firefox } = require(path.join(root, "immerse-src/node_modules/playwright"));
const { expect } = require(path.join(root, "immerse-src/node_modules/@playwright/test"));
const data = path.join(root, "build-macos/django-security");
const manifest = JSON.parse(fs.readFileSync(path.join(data, "manifest.json"), "utf8"));
const dashboard = JSON.parse(fs.readFileSync(path.join(data, "dashboard.json"), "utf8"));
const flows = JSON.parse(fs.readFileSync(path.join(data, "flow-manifest.json"), "utf8"));

async function main() {
  const report = [];
  for (const [name, engine] of Object.entries({ chromium, firefox })) {
    const browser = await engine.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1600, height: 1100 } });
    const errors = [];
    const writes = [];
    let sourceQueries = 0;
    page.on("pageerror", error => errors.push(error.stack || error.message));
    page.on("request", request => {
      const body = request.postDataBuffer();
      if (!body) return;
      for (const method of ["create_dashboard", "replace_dashboard", "delete_dashboard"]) {
        if (body.includes(Buffer.from(method))) writes.push(method);
      }
      if (body.includes(Buffer.from("sql_execute")) && body.includes(Buffer.from("django_sec_"))) sourceQueries++;
    });
    const count = page.getByTestId("security-result-count");
    try {
      await page.goto(dashboard.url, { waitUntil: "networkidle" });
      for (const check of dashboard.kpi_checks) {
        await expect(page.locator(`#chart${check.chart_id} .number-chart-wrapper > span`))
          .toHaveText(Number(check.value).toLocaleString("en-US"), { timeout: 30000 });
      }
      for (const id of [6, 7, 8, 9]) {
        await page.locator(`#chart${id}`).scrollIntoViewIfNeeded();
        await page.waitForTimeout(200);
      }
      await expect(page.locator(".chart-errors,.dialog-message")).toHaveCount(0);
      expect(await page.locator("#chart6 g.row rect").count()).toBeGreaterThan(0);
      expect(await page.locator("#chart7 g.pie-slice path").count()).toBeGreaterThan(0);
      console.log(`PASS: ${name}: native dashboard KPIs, charts, and evidence table`);

      const sourceLink = page.getByRole("link", { name: "Open the source investigation view", exact: true });
      await expect(sourceLink).toHaveCount(1);
      expect(await sourceLink.getAttribute("target")).toBeNull();
      await sourceLink.click();
      await expect(count).toHaveText(`${flows.snapshot.flow_count} flows`, { timeout: 30000 });
      await expect(page.locator(".sc-provenance")).toContainText(`HeavyDB Metal ${flows.snapshot.engine_version}`);
      await expect(page.getByTestId("security-flow")).toContainText("Not a confirmed vulnerability");
      await expect(page.locator(".sc-limits")).toContainText(`Unmodeled sink signals: ${flows.snapshot.unmapped_sink_count}`);
      await page.getByLabel("Source kind", { exact: true }).selectOption("HTTP request");
      await expect(count).toHaveText(`${flows.snapshot.request_flow_count} flows`);
      await page.getByLabel("Source kind", { exact: true }).selectOption("Caller parameter");
      await expect(count).toHaveText(`${flows.snapshot.parameter_flow_count} flows`);
      await expect(page.getByTestId("security-flow")).toContainText("External attacker control has not been established");
      await page.getByRole("button", { name: "Reset filters", exact: true }).click();
      await page.getByLabel("Boundary type", { exact: true }).selectOption("SQL");
      await expect(count).toHaveText(`${flows.categories.SQL} flows`);
      await expect(page.getByTestId("security-flow").locator("strong").first()).toHaveText("Caller parameter to SQL text");
      await expect(page.getByTestId("security-flow")).toContainText("SQL text excludes bound parameter values");
      const firstStep = page.locator(".sc-trace button").first();
      const sourceLine = Number((await firstStep.innerText()).match(/line (\d+)/)[1]);
      await firstStep.click();
      await expect(page.locator(`[data-testid="security-source"] [data-line="${sourceLine}"]`)).toHaveClass("is-selected");
      await page.locator(".sc-trace button").last().click();
      await expect(page).toHaveURL(/flow=\d+/);
      const flowPermalink = page.url();
      const flowId = new URL(flowPermalink).searchParams.get("flow");
      await page.reload({ waitUntil: "networkidle" });
      await expect(page.getByTestId("security-flow")).toBeVisible();
      expect(new URL(page.url()).searchParams.get("flow")).toBe(flowId);
      await page.locator(".sc-flow-controls summary").click();
      await expect(page.locator(".sc-flow-controls")).toContainText("not proven guards");
      await page.screenshot({ path: path.join(data, `security-native-flows-${name}.png`), fullPage: true });
      await page.getByRole("link", { name: "Overview dashboard", exact: true }).click();
      await page.waitForURL(dashboard.url);
      await page.getByRole("link", { name: "Open the source investigation view", exact: true }).click();
      await expect(count).toHaveText(`${flows.snapshot.flow_count} flows`, { timeout: 30000 });
      await page.getByRole("button", { name: "All signals", exact: true }).click();
      await expect(count).toHaveText(`${manifest.counts.signals} signals`);
      console.log(`PASS: ${name}: native mappings, source kinds, SQL text, trace lines, flow permalinks, and reciprocal dashboard links`);
      await expect(page.locator("h1")).toHaveText("Django Security Atlas");
      await expect(page.locator(".sc-provenance")).toContainText(manifest.snapshot.commit_sha);
      await expect(page.getByTestId("security-source")).toBeVisible();
      expect(await page.locator("h1").evaluate(element => element.getBoundingClientRect().top)).toBeGreaterThanOrEqual(0);
      await page.getByLabel("Boundary type", { exact: true }).selectOption("SQL");
      await expect(count).toHaveText(`${manifest.categories.SQL} signals`);
      await expect(page.getByTestId("security-evidence")).toContainText("parameter binding");
      await page.getByLabel("Evidence role", { exact: true }).selectOption("control");
      await expect(count).toHaveText("0 signals");
      await expect(page.getByText("No signals match these filters.")).toBeVisible();
      await page.getByRole("button", { name: "Reset filters", exact: true }).click();
      await expect(count).toHaveText(`${manifest.counts.signals} signals`);
      await page.getByLabel("Evidence role", { exact: true }).selectOption("trust override");
      await expect(count).toHaveText(`${manifest.roles["trust override"]} signals`);
      await page.locator(".sc-signal").first().click();
      await expect(page.getByTestId("security-evidence")).toContainText("Not a confirmed vulnerability");
      console.log(`PASS: ${name}: live category, role, empty-result, and reset filters`);

      await page.getByRole("button", { name: "Reset filters", exact: true }).click();
      await expect(count).toHaveText(`${manifest.counts.signals} signals`);
      await page.getByLabel("Search scope or path").fill("SQLCompiler.execute_sql");
      await page.getByRole("button", { name: "Search", exact: true }).click();
      await expect(count).not.toHaveText(`${manifest.counts.signals} signals`);
      await expect(page.locator(".sc-signal").first()).toBeVisible();
      await expect(page.getByTestId("security-evidence")).toContainText("SQL");
      const asSql = page.locator(".sc-relations button").filter({ hasText: /^django\.db\.models\.sql\.compiler\.SQLCompiler\.as_sql$/ }).first();
      await asSql.click();
      await expect(page.getByTestId("security-evidence")).toContainText("django.db.models.sql.compiler.SQLCompiler.as_sql");
      await expect(page.locator(".sc-relations")).toContainText("Static references only");
      await page.getByRole("checkbox", { name: "Zoom to scope" }).check();
      await expect(page.getByRole("checkbox", { name: "Zoom to scope" })).toBeChecked();
      await page.locator(".sc-cst summary").click();
      await expect(page.locator(".sc-cst")).toContainText("function_definition");

      const fileId = Number(new URL(page.url()).searchParams.get("file"));
      const expectedSource = JSON.parse(execFileSync("python3", ["-c",
        "import sys;sys.path.insert(0,'dev-tools/macos');from vulnerability_db import HeavyDB\nwith HeavyDB() as db: print(db.sql('SELECT source_json FROM django_sec_files WHERE file_id='+str(int(sys.argv[1])))[0][0])",
        String(fileId)], { cwd: root, encoding: "utf8", timeout: 30000 }));
      expect(await page.locator('[data-testid="security-source"] > div > code').allTextContents())
        .toEqual(expectedSource.split("\n").map(line => line || " "));
      expect(await page.locator('[data-testid="security-source"] script,[data-testid="security-source"] a,[data-testid="security-source"] img').count()).toBe(0);
      const sourceHref = await page.getByRole("link", { name: "Pinned source on GitHub" }).getAttribute("href");
      expect(sourceHref).toContain(`/blob/${manifest.snapshot.commit_sha}/django/`);
      const permalink = page.url();
      await page.reload({ waitUntil: "networkidle" });
      await expect(page.getByTestId("security-evidence")).toContainText("django.db.models.sql.compiler.SQLCompiler.as_sql");
      console.log(`PASS: ${name}: call-candidate navigation, scope zoom, syntax containment, exact source, and permalink reload`);

      await page.getByLabel("Search scope or path").fill("' OR 1=1 --");
      await page.getByRole("button", { name: "Search", exact: true }).click();
      await expect(count).toHaveText("0 signals");
      await page.getByRole("button", { name: "Reset filters", exact: true }).click();
      await expect(count).toHaveText(`${manifest.counts.signals} signals`);
      await page.screenshot({ path: path.join(data, `security-atlas-${name}.png`), fullPage: true });
      const mobile = await browser.newPage({ viewport: { width: 390, height: 844 } });
      mobile.on("pageerror", error => errors.push(error.message));
      await mobile.goto(flowPermalink, { waitUntil: "networkidle" });
      await expect(mobile.getByTestId("security-flow")).toBeVisible();
      expect(new URL(mobile.url()).searchParams.get("flow")).toBe(flowId);
      expect(await mobile.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      await mobile.screenshot({ path: path.join(data, `security-native-flows-mobile-${name}.png`), fullPage: true });
      await mobile.goto(permalink, { waitUntil: "networkidle" });
      await expect(mobile.getByTestId("security-evidence")).toContainText("SQLCompiler.as_sql");
      expect(await mobile.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      await mobile.screenshot({ path: path.join(data, `security-atlas-mobile-${name}.png`), fullPage: true });
      await mobile.close();
      await page.getByRole("link", { name: "All dashboards", exact: true }).click();
      await page.waitForURL("**/heavyai/dashboards");
      expect(errors).toEqual([]);
      expect(writes).toEqual([]);
      expect(sourceQueries).toBeGreaterThan(20);
      report.push({ browser: name, sourceQueries, permalink, flowPermalink, errors, writes });
      console.log(`PASS: ${name}: literal-safe search, mobile layout, navigation, and no saved-state writes`);
    } catch (error) {
      console.error("FAIL:", name, error, "ERRORS:", errors);
      console.error("ALERTS:", await page.getByRole("alert").allInnerTexts());
      await page.screenshot({ path: path.join(data, `security-failure-${name}.png`), fullPage: true });
      throw error;
    } finally {
      await browser.close();
    }
  }
  fs.writeFileSync(path.join(data, "browser-verification.json"), JSON.stringify(report, null, 2) + "\n");
  console.log("PASS: Django security dashboard and source investigation in Chromium and Firefox");
}

main().catch(error => { console.error(error); process.exitCode = 1; });
