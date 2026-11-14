#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "../..");
const { chromium, firefox } = require(path.join(root, "immerse-src/node_modules/playwright"));
const { expect } = require(path.join(root, "immerse-src/node_modules/@playwright/test"));
const data = path.join(root, "build-macos/vulnerability-data");

async function main() {
  const manifest = JSON.parse(fs.readFileSync(path.join(data, "dashboards.json"), "utf8"));
  const report = [];
  for (const [name, engine] of Object.entries({ chromium, firefox })) {
    const browser = await engine.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1680, height: 1100 } });
    const sliceErrors = [];
    let faultMessage = null;
    let failedQueries = 0;
    let sqlQueries = 0;
    let chartQueries = 0;
    page.on("pageerror", error => {
      if (/slice/i.test(error.message)) sliceErrors.push(error.message);
    });
    await page.route("http://127.0.0.1:6273/", async route => {
      const body = route.request().postDataBuffer();
      if (!body?.includes(Buffer.from("sql_execute"))) return route.continue();
      sqlQueries++;
      if (body.includes(Buffer.from("GROUP BY"))) chartQueries++;
      if (faultMessage === null || !body.includes(Buffer.from("cvss_band"))) return route.continue();
      failedQueries++;
      const methodLength = body.readInt32BE(4);
      const header = Buffer.from(body.subarray(0, 12 + methodLength));
      header.writeUInt32BE(0x80010002, 0);
      const message = Buffer.from(faultMessage);
      const length = Buffer.alloc(4);
      length.writeInt32BE(message.length);
      return route.fulfill({ status: 200, contentType: "application/vnd.apache.thrift.binary",
        body: Buffer.concat([header, Buffer.from([12, 0, 1, 11, 0, 1]), length, message, Buffer.from([0, 0])]) });
    });
    async function refresh() {
      // Query results stay cached for five seconds.
      await page.waitForTimeout(5500);
      const before = chartQueries;
      await page.getByTestId("refresh-now-btn").press("Enter");
      await expect.poll(() => chartQueries).toBeGreaterThan(before);
      await page.waitForLoadState("networkidle");
      await expect(page.locator(".loading-gfx-refresh")).toHaveClass(/loading-gfx-hide/);
    }
    async function checkKpis(dashboard) {
      for (const check of dashboard.kpi_checks) {
        await expect(page.locator(`#chart${check.chart_id} .number-chart-wrapper > span`))
          .toHaveText(Number(check.value).toLocaleString("en-US"), { timeout: 30000 });
      }
    }
    try {
      for (const dashboard of manifest.dashboards) {
        await page.goto(`http://127.0.0.1:6273/heavyai/dashboard/${dashboard.id}`, { waitUntil: "networkidle" });
        await expect(page.getByTestId("dashboard-title-placeholder")).toContainText(dashboard.title);
        for (const chart of dashboard.charts) {
          await page.locator(`#chart${chart.id}`).scrollIntoViewIfNeeded();
          await page.waitForTimeout(100);
        }
        await page.waitForLoadState("networkidle");
        await checkKpis(dashboard);
        for (let attempt = 0; attempt < 3; attempt++) {
          await refresh();
          await checkKpis(dashboard);
          await expect(page.locator(".dialog-message,.chart-errors")).toHaveCount(0);
        }
        console.log(`PASS: ${name} dashboard ${dashboard.id}: three real query refreshes preserve all KPIs`);
        if (dashboard.id === 3) {
          for (const message of ["", "Refresh regression: planned query failure"]) {
            const before = failedQueries;
            faultMessage = message;
            await refresh();
            expect(failedQueries).toBe(before + 1);
            await expect(page.locator(".dialog-message"))
              .toHaveText(message || "An unknown error occurred.");
            expect(sliceErrors).toEqual([]);
            faultMessage = null;
            await page.getByRole("button", { name: /^ok$/i }).click();
            await refresh();
            await checkKpis(dashboard);
            await expect(page.locator(".dialog-message,.chart-errors")).toHaveCount(0);
            expect(await page.locator("#chart8 g.pie-slice path").count()).toBeGreaterThan(0);
            console.log(`PASS: ${name}: ${message ? "named" : "empty"} query error stays an error; the next refresh recovers`);
          }
        }
      }
      expect(sliceErrors).toEqual([]);
      report.push({ browser: name, sqlQueries, chartQueries, failedQueries, sliceErrors });
    } catch (error) {
      console.error("FAIL:", name, error);
      console.error("MESSAGES:", await page.locator(".dialog-message,.chart-errors").allInnerTexts());
      await page.screenshot({ path: path.join(root, `build-macos/refresh-failure-${name}.png`), fullPage: true });
      throw error;
    } finally {
      await browser.close();
    }
  }
  fs.writeFileSync(path.join(data, "dashboard-refresh-verification.json"), JSON.stringify(report, null, 2) + "\n");
  console.log("PASS: Chromium and Firefox refresh, query errors, and recovery; no saved state changed");
}

main().catch(error => { console.error(error); process.exitCode = 1; });
