#!/usr/bin/env node

const path = require("node:path");
const fs = require("node:fs");
const root = path.resolve(__dirname, "../..");
const { chromium } = require(path.join(root, "immerse-src/node_modules/playwright"));
const { expect } = require(path.join(root, "immerse-src/node_modules/@playwright/test"));

async function main() {
  const logPath = path.join(root, "build-macos/heavydb-console.log");
  const logOffset = fs.statSync(logPath).size;
  const dashboardName = "Metal SQL Validation " + new Date().toISOString();
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on("pageerror", error => {
    errors.push(error.message);
    console.error("PAGE ERROR:", error.message);
  });
  try {
    await page.goto("http://127.0.0.1:6273", { waitUntil: "domcontentloaded" });
    await page.waitForURL("**/heavyai/dashboards");
    await expect(page.locator("input[type=password]")).toHaveCount(0);
    await page.getByText("New Dashboard", { exact: true }).click();
    await page.getByText("Add Chart", { exact: true }).first().click();
    await page.getByText(/^number$/i).click();
    await page.getByText("Select Data Source", { exact: true }).click();
    await page.getByText("metal_backend_validation", { exact: true }).click();
    await expect(page.getByText("Connect to a Data Source", { exact: true })).toHaveCount(0);
    await page.locator(".invisible-overlay").waitFor({ state: "hidden" });
    await page.locator(".selector-loading").waitFor({ state: "hidden" });
    await page.locator(".selector-box.button.inactive").waitFor({ state: "hidden" });
    await page.locator("#measure-add-0").hover();
    // Let the legacy selector finish its hover update before the click.
    await page.waitForTimeout(150);
    await page.locator("#measure-add-0").click();
    const measure = page.getByPlaceholder("Select a measure");
    await measure.fill("# Records");
    await measure.press("Enter");
    await page.keyboard.press("Enter");
    await expect(page.locator(".number-chart-wrapper > span")).toHaveText("99,911");
    await page.getByTestId("chart-edit-apply").click();
    await page.getByTestId("dashboard-title-placeholder").click();
    await page.getByTestId("dashboard-title-input").fill(dashboardName);
    await page.getByTestId("dashboard-title-input").press("Enter");
    await page.getByTestId("save-dashboard-button").click();
    await page.locator('.success[data-testid="save-dashboard-button"]').waitFor();
    await page.reload({ waitUntil: "networkidle" });
    await expect(page.getByTestId("dashboard-title-placeholder")).toContainText(dashboardName);
    await expect(page.locator(".number-chart-wrapper > span")).toHaveText("99,911");
    await page.mouse.move(1000, 300);
    await page.screenshot({ path: path.join(root, "build-macos/immerse-dashboard.png"),
      fullPage: true });
    if (errors.length) throw new Error(errors.join("\n"));
    const evidence = fs.readFileSync(logPath).subarray(logOffset).toString("utf8");
    if (!/Metal SQL executed:.* rows=100005 aggregates=1 /.test(evidence)) {
      throw new Error("The browser chart did not record real Metal SQL execution");
    }
    fs.writeFileSync(path.join(root, "build-macos/verified-dashboard-url.txt"), page.url() + "\n");
    console.log("PASS: automatic local login, source selection, Metal COUNT chart, save and reload");
    console.log("Dashboard:", page.url());
  } finally {
    await browser.close();
  }
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
