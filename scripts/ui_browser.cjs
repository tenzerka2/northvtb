/* Browser E2E runs against the real sandbox started by ui_demo.py. */
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
(async () => {
  const browser = await chromium.launch({ headless: true });
  const artifacts =
    process.env.NORTH_TEST_ARTIFACTS || "/tmp/north-ui-screenshots";
  fs.mkdirSync(artifacts, { recursive: true });
  const failures = [];
  try {
    for (const width of [1440, 390]) {
      const page = await browser.newPage({
        viewport: { width, height: 1000 },
        deviceScaleFactor: 1,
      });
      page.on("pageerror", (e) => failures.push(e.message));
      await page.goto(process.env.NORTH_DEMO_URL);
      await page
        .getByLabel("Ключ доступа к демо")
        .fill(process.env.NORTH_OWNER_TOKEN);
      await page.getByRole("button", { name: "Войти в NORTH" }).click();
      await page
        .getByRole("heading", { name: "Поручения", exact: true })
        .waitFor();
      const snap = async (name) => {
        await page.evaluate(() => document.fonts.ready);
        assert(
          await page.evaluate(
            () => document.documentElement.scrollWidth <= innerWidth,
          ),
          `overflow at ${width}: ${name}`,
        );
        await page.screenshot({
          path: path.join(artifacts, `${width}-${name}.png`),
          fullPage: true,
        });
      };
      await snap("mandates");
      await page
        .getByRole("link", { name: "Создать поручение", exact: true })
        .first()
        .click();
      const connect = page.getByRole("button", {
        name: "Подключить агента «Закупки»",
        exact: true,
      });
      if (await connect.count()) await connect.click();
      await page
        .getByLabel("Название поручения")
        .fill("Купить монитор — " + width);
      await snap("new");
      await page
        .getByRole("button", { name: "Создать и разрешить поиск" })
        .click();
      await page
        .getByRole("heading", { name: "Предложения", exact: true })
        .waitFor();
      await snap("offers");
      await page
        .getByRole("button", { name: "Посмотреть причину", exact: true })
        .click();
      await page
        .getByRole("heading", { name: "Покупка заблокирована" })
        .waitFor();
      await snap("blocked");
      await page
        .getByRole("link", { name: "Выбрать другое предложение" })
        .click();
      await page
        .getByRole("button", { name: "Посмотреть предложение", exact: true })
        .click();
      await page
        .getByRole("heading", { name: "Подтвердите покупку" })
        .waitFor();
      await page.reload();
      await page
        .getByRole("heading", { name: "Подтвердите покупку" })
        .waitFor();
      await snap("confirmation");
      await page
        .getByRole("button", { name: /Подтвердить и купить за/ })
        .click();
      await page
        .getByRole("heading", { name: "Покупка оплачена" })
        .waitFor({ timeout: 30000 });
      await snap("success");
      await page.reload();
      await page.getByRole("heading", { name: "Покупка оплачена" }).waitFor();
      await page.getByRole("link", { name: "Открыть операции" }).click();
      await page
        .getByRole("heading", { name: "Операции", exact: true })
        .waitFor();
      await snap("operations");
      await page
        .getByRole("link", { name: "Агенты", exact: true })
        .filter({ visible: true })
        .first()
        .click();
      await page
        .getByRole("heading", { name: "Агенты", exact: true })
        .waitFor();
      await snap("agents");
      await page
        .getByRole("button", { name: "Отозвать доступ", exact: true })
        .click();
      await page
        .getByRole("button", { name: "Подтвердить", exact: true })
        .click();
      await page.getByText("Доступ отозван", { exact: true }).waitFor();
      await page.getByRole("button", { name: "Выйти", exact: true }).click();
      await page.getByRole("button", { name: "Войти в NORTH" }).waitFor();
      await page.close();
    }
    assert.deepEqual(failures, []);
    console.log(
      "BROWSER E2E PASSED: desktop and mobile, overflow, confirmation reload, payment, history, revoke, logout",
    );
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
