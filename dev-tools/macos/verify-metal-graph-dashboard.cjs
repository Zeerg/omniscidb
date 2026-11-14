#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "../..");
const { chromium, firefox } = require(path.join(root, "immerse-src/node_modules/playwright"));
const { expect } = require(path.join(root, "immerse-src/node_modules/@playwright/test"));
const data = path.join(root, "build-macos/metal-graph-performance");
const dashboard = JSON.parse(fs.readFileSync(path.join(data, "dashboard.json"), "utf8"));
const measured = JSON.parse(fs.readFileSync(path.join(data, "measurements.json"), "utf8"));
const baseline = JSON.parse(fs.readFileSync(path.join(data, "dashboards-before.json"), "utf8"));

async function main() {
  const reports = [];
  for (const [name, engine] of Object.entries({ chromium, firefox })) {
    const browser = await engine.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1680, height: 1100 } });
    const errors = [];
    const writes = [];
    let queries = 0;
    page.on("pageerror", error => errors.push(error.stack || error.message));
    page.on("request", request => {
      const body = request.postDataBuffer();
      if (!body) return;
      for (const method of ["create_dashboard", "replace_dashboard", "delete_dashboard"]) {
        if (body.includes(Buffer.from(method))) writes.push(method);
      }
      if (body.includes(Buffer.from("sql_execute")) && body.includes(Buffer.from(dashboard.table))) queries++;
    });
    async function check() {
      await expect(page.getByTestId("dashboard-title-placeholder")).toContainText(dashboard.title);
      for (const kpi of dashboard.kpi_checks) {
        await expect(page.locator(`#chart${kpi.chart_id} .number-chart-wrapper > span`))
          .toHaveText(Number(kpi.value).toLocaleString("en-US"), { timeout: 30000 });
      }
      await page.locator("#chart6").scrollIntoViewIfNeeded();
      await expect.poll(() => page.locator("#chart6 path.line").count(), { timeout: 30000 }).toBeGreaterThanOrEqual(2);
      const paths = await page.locator("#chart6 path.line").evaluateAll(elements => elements.map(element => ({
        d: element.getAttribute("d"), stroke: getComputedStyle(element).stroke
      })));
      expect(paths.every(item => item.d && !item.d.includes("NaN"))).toBe(true);
      expect(new Set(paths.map(item => item.stroke)).size).toBeGreaterThanOrEqual(2);
      await page.locator("#chart7").scrollIntoViewIfNeeded();
      await expect(page.locator("#chart7")).toContainText("GPU command", { timeout: 30000 });
      await expect(page.locator("#chart7")).toContainText("SQL round trip");
      expect(await page.locator("#chart7 table tr").count()).toBeGreaterThanOrEqual(7);
      await expect(page.locator("#chart8")).toContainText("Dashboard refresh does not rerun the benchmark");
      await expect(page.locator("#chart8")).toContainText("No optimized-CPU speedup");
      await expect(page.locator(".chart-errors,.dialog-message")).toHaveCount(0);
    }
    try {
      await page.goto(dashboard.url, { waitUntil: "networkidle" });
      await check();
      await page.screenshot({ path: path.join(data, `dashboard-${name}.png`), fullPage: true });
      await page.reload({ waitUntil: "networkidle" });
      await check();
      await page.getByRole("link", { name: "Inspect the source-to-sink mappings", exact: true }).click();
      await expect(page.getByTestId("security-result-count")).toHaveText(
        `${Math.max(...measured.cases.map(item => item.pair_count))} flows`, { timeout: 30000 });
      await page.getByRole("link", { name: "All dashboards", exact: true }).click();
      await page.waitForURL("**/heavyai/dashboards");
      await page.getByText(dashboard.title, { exact: true }).click();
      await check();
      const mobile = await browser.newPage({ viewport: { width: 390, height: 844 } });
      mobile.on("pageerror", error => errors.push(error.message));
      await mobile.goto(dashboard.url, { waitUntil: "networkidle" });
      await expect(mobile.getByTestId("dashboard-title-placeholder")).toContainText(dashboard.title);
      await expect(mobile.locator("#chart2 .number-chart-wrapper > span")).toHaveText(
        String(dashboard.kpi_checks[0].value), { timeout: 30000 });
      const mobileLayout = await mobile.evaluate(() => ({ viewport: innerWidth,
        rootWidth: document.getElementById("root").getBoundingClientRect().width,
        scrollWidth: document.documentElement.scrollWidth }));
      await mobile.screenshot({ path: path.join(data, `dashboard-mobile-${name}.png`), fullPage: true });
      if (mobileLayout.scrollWidth > mobileLayout.viewport) {
        const priorId = Object.keys(baseline)[0];
        await mobile.goto(`http://127.0.0.1:6273/heavyai/dashboard/${priorId}`, { waitUntil: "networkidle" });
        expect(await mobile.locator("#root").evaluate(element => element.getBoundingClientRect().width))
          .toBe(mobileLayout.rootWidth);
        expect(mobileLayout.rootWidth).toBeGreaterThan(mobileLayout.viewport);
      }
      await mobile.close();
      expect(errors).toEqual([]);
      expect(writes).toEqual([]);
      expect(queries).toBeGreaterThan(6);
      reports.push({ browser: name, queries, errors, writes, mobileLayout, url: dashboard.url });
      console.log(`PASS: ${name}: native KPIs, two timing series, measured ranges, reload, source link, and dashboard-list navigation`);
      console.log(`Narrow-screen shell: viewport=${mobileLayout.viewport}, root=${mobileLayout.rootWidth}, scroll=${mobileLayout.scrollWidth}. Existing native dashboards use the same desktop-width root.`);
    } catch (error) {
      console.error("FAIL:", name, error, "PAGE ERRORS:", errors);
      console.error("CHART ERRORS:", await page.locator(".chart-errors,.dialog-message").allTextContents());
      await page.screenshot({ path: path.join(data, `dashboard-failure-${name}.png`), fullPage: true });
      throw error;
    } finally {
      await browser.close();
    }
  }
  fs.writeFileSync(path.join(data, "browser-verification.json"), JSON.stringify(reports, null, 2) + "\n");
}

main().catch(error => { console.error(error); process.exitCode = 1; });
