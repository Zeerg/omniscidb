#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const root = path.resolve(__dirname, "../..");
const { chromium, firefox } = require(path.join(root, "immerse-src/node_modules/playwright"));
const { expect } = require(path.join(root, "immerse-src/node_modules/@playwright/test"));
const data = path.join(root, "build-macos/vulnerability-data");

async function main() {
  const manifest = JSON.parse(fs.readFileSync(path.join(data, "dashboards.json"), "utf8"));
  const dashboard = manifest.dashboards.find(item => item.id === 3);
  const total = dashboard.kpi_checks.find(item => item.chart_id === "2" || item.chart_id === 2).value;
  const report = [];
  for (const [name, engine] of Object.entries({ chromium, firefox })) {
    const browser = await engine.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const errors = [];
    const warnings = [];
    const queries = [];
    page.on("pageerror", error => errors.push(error.stack || error.message));
    page.on("console", message => {
      if (!["error", "warning", "warn"].includes(message.type())) return;
      const text = message.text();
      if (/timeBin|missing identifier|not a valid regexp|uncaught at/i.test(text)) errors.push(text);
      else warnings.push(text);
    });
    page.on("request", request => {
      const body = request.postDataBuffer();
      if (!body?.includes(Buffer.from("sql_execute"))) return;
      const start = body.indexOf(Buffer.from("SELECT "));
      if (start >= 4) queries.push(body.subarray(start, start + body.readInt32BE(start - 4)).toString());
    });
    const chart = page.locator("#chart11");
    const card = page.locator(".react-grid-item").filter({ has: chart });
    const kpi = page.locator("#chart2 .number-chart-wrapper > span");
    async function checkFilter(label, before) {
      await expect(kpi).not.toHaveText(Number(total).toLocaleString("en-US"));
      await page.waitForLoadState("networkidle");
      await page.waitForTimeout(400);
      await page.waitForLoadState("networkidle");
      const query = queries.slice(before).filter(sql =>
        /^SELECT COUNT\(\*\) AS val FROM vuln_published WHERE /.test(sql) && sql.includes("published_month")).at(-1);
      expect(query).toBeTruthy();
      const expected = Number(execFileSync("python3", ["-c",
        "import sys;sys.path.insert(0,'dev-tools/macos');from vulnerability_db import HeavyDB\nwith HeavyDB() as db: print(db.sql(sys.argv[1])[0][0])",
        query], { cwd: root, encoding: "utf8", timeout: 30000 }).trim());
      expect(expected).toBeGreaterThan(0);
      expect(expected).toBeLessThan(Number(total));
      await expect(kpi).toHaveText(expected.toLocaleString("en-US"));
      expect(errors).toEqual([]);
      console.log(`PASS: ${name}: ${label}: ${expected} CVEs match a separate SQL session`);
      return { label, count: expected, query };
    }
    async function clear() {
      await card.locator(".delete-chart-filters").click();
      await expect(kpi).toHaveText(Number(total).toLocaleString("en-US"));
      await page.waitForLoadState("networkidle");
      expect(errors).toEqual([]);
    }
    try {
      await page.goto(dashboard.url, { waitUntil: "networkidle" });
      await chart.scrollIntoViewIfNeeded();
      await expect(kpi).toHaveText(Number(total).toLocaleString("en-US"));
      await chart.hover();
      for (const axis of ["x", "y"]) {
        await expect(chart.locator(`.${axis}-axis-label`)).toBeHidden();
        const label = card.locator(`.chart-axis-overlay .${axis}-axis .axis-display`);
        await expect(label).toHaveCount(1);
        await expect(label).toBeVisible();
      }
      console.log(`PASS: ${name}: one label per axis, including on hover`);
      const day = chart.locator(".range-start-day");
      await expect(day).not.toHaveValue("");
      let before = queries.length;
      await day.fill("01-01-2010");
      await expect(day).toHaveValue("01-01-2010");
      await day.press("Enter");
      const dateInput = await checkFilter("date input", before);
      expect(dateInput.query).toContain("2010-01-01");
      await clear();
      const box = await chart.locator(".brush rect.background").boundingBox();
      expect(box).toBeTruthy();
      before = queries.length;
      await page.mouse.move(box.x + box.width * 0.3, box.y + box.height / 2);
      await page.mouse.down();
      await page.mouse.move(box.x + box.width * 0.6, box.y + box.height / 2, { steps: 12 });
      await page.mouse.up();
      const drag = await checkFilter("drag selection", before);
      await expect(chart.locator(".x-axis-label")).toBeHidden();
      await expect(chart.locator(".y-axis-label")).toBeHidden();
      await clear();
      await page.locator('a[href="/heavyai/dashboards"]').click();
      await page.waitForURL("**/heavyai/dashboards");
      await page.getByText(dashboard.title, { exact: true }).click();
      await expect(page.getByTestId("dashboard-title-placeholder")).toContainText(dashboard.title);
      await chart.scrollIntoViewIfNeeded();
      await expect(kpi).toHaveText(Number(total).toLocaleString("en-US"));
      await page.waitForLoadState("networkidle");
      expect(errors).toEqual([]);
      report.push({ browser: name, dateInput, drag, errors, warnings });
      console.log(`PASS: ${name}: clear, dashboard-list navigation, and reopening without runtime errors`);
    } catch (error) {
      console.error("FAIL:", name, error, "ERRORS:", errors);
      console.error("DATE INPUTS:", await chart.locator(".range-display input").evaluateAll(inputs =>
        inputs.map(input => ({ value: input.value, previous: input.getAttribute("value"),
          className: input.className, keyHandler: Boolean(input.__onkeydown) }))));
      console.error("RECENT SQL:", queries.slice(-5));
      await page.screenshot({ path: path.join(root, `build-macos/line-failure-${name}.png`), fullPage: true });
      throw error;
    } finally {
      await browser.close();
    }
  }
  fs.writeFileSync(path.join(data, "line-chart-verification.json"), JSON.stringify(report, null, 2) + "\n");
  console.log("PASS: both browsers; no dashboards saved");
}

main().catch(error => { console.error(error); process.exitCode = 1; });
