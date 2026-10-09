"use strict";
const $ = (s) => document.querySelector(s);
const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const money = (n) =>
  new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 2 }).format(
    (n || 0) / 100,
  ) + " ₽";
const date = (n) =>
  new Date(typeof n === "number" ? n * 1000 : n).toLocaleDateString("ru-RU", {
    day: "numeric",
    month: "long",
  });
const icon = (name) =>
  `<span class="icon ${name}" aria-hidden="true"><img src="/assets/${name}.svg" alt=""></span>`;
const merchant = (id) =>
  ({ dns: "DNS", citilink: "Ситилинк", technopark: "Технопарк" })[id] || id;
const labels = {
  ACTIVE: "Активно",
  DRAFT: "Черновик",
  REVOKED: "Отозвано",
  EXPIRED: "Срок истёк",
  CONSUMED: "Выполнено",
  SUCCEEDED: "Оплачено",
  FAILED: "Не выполнено",
  CANCELLED: "Отменено",
  UNKNOWN: "Уточняем статус",
  PENDING: "Ожидаем оплату",
  SUBMITTED: "Ожидаем ответ",
  ALLOW: "Условия соблюдены",
  ASK_USER: "Нужно решение",
  DENY: "Покупка заблокирована",
};
const badge = (state, text) =>
  `<span class="badge ${["ASK_USER", "UNKNOWN", "PENDING", "SUBMITTED"].includes(state) ? "amber" : ["ALLOW", "SUCCEEDED", "CONSUMED"].includes(state) ? "green" : ["DENY", "FAILED", "REVOKED"].includes(state) ? "red" : state === "ACTIVE" ? "blue" : ""}">${esc(text || labels[state] || state)}</span>`;
const ruleNames = {
  AGENT_MATCH: "Покупку выполняет назначенный агент",
  AGENT_ACTIVE: "Доступ агента активен",
  OWNER_MATCH: "Владелец поручения проверен",
  MANDATE_MATCH: "Поручение совпадает",
  MANDATE_ACTIVE: "Поручение активно",
  MANDATE_NOT_EXPIRED: "Срок поручения не истёк",
  TRANSACTION_VALID: "Данные покупки корректны",
  ACTION_MATCH: "Разрешена покупка",
  PURPOSE_MATCH: "Назначение покупки совпадает",
  PRODUCT_MATCH: "Товар соответствует поручению",
  CATEGORY_MATCH: "Категория совпадает",
  CONDITION_MATCH: "Состояние товара совпадает",
  AMOUNT_WITHIN_LIMIT: "Сумма в пределах лимита",
  CURRENCY_MATCH: "Валюта — рубли",
  MERCHANT_ALLOWED: "Поставщик разрешён",
  OFFER_AUTHENTIC: "Предложение проверено",
  MERCHANT_TRUST_SUFFICIENT: "Поставщик в проверенном каталоге",
  RISK_ACCEPTABLE: "Уровень риска допустим",
  USAGE_AVAILABLE: "Покупка ещё не выполнена",
};
const ruleFailures = {
  AMOUNT_WITHIN_LIMIT: "Сумма выше вашего лимита",
  MERCHANT_ALLOWED: "Поставщик не разрешён поручением",
  MERCHANT_TRUST_SUFFICIENT: "Поставщик не прошёл проверку",
  AGENT_ACTIVE: "Доступ агента отозван",
  MANDATE_ACTIVE: "Поручение не активно",
  MANDATE_NOT_EXPIRED: "Срок поручения истёк",
  USAGE_AVAILABLE: "Разрешение уже использовано или зарезервировано",
  OFFER_AUTHENTIC: "Данные предложения изменились",
  PRODUCT_MATCH: "Товар не совпадает с поручением",
  RISK_ACCEPTABLE: "Уровень риска выше разрешённого",
};
const eventNames = {
  "agent.registered": "Агент подключён",
  "agent.revoked": "Доступ агента отозван",
  "mandate.created": "Поручение создано",
  "mandate.approved": "Поручение подтверждено",
  "mandate.revoked": "Поручение отозвано",
  "transaction.proposed": "Агент предложил покупку",
  "policy.evaluated": "Условия покупки проверены",
  "authorization.issued": "Покупка разрешена",
  "authorization.denied": "Покупка требует решения или заблокирована",
  "challenge.approved": "Новое предложение подтверждено",
  "grant.consumed": "Покупка передана на оплату",
  "payment.succeeded": "Оплата завершена",
  "payment.unknown": "Уточняется результат оплаты",
};
let state = {
  owner: "",
  agents: [],
  mandates: [],
  payments: [],
  events: [],
  digests: {},
};
let authenticated = false, homeOffers = [];
let tab = "active",
  selectedAgent = "",
  selectedPayment = "",
  offers = [],
  pending = null,
  busy = false,
  routeVersion = 0,
  poll = null;
const app = $("#app");
function notify(text) {
  $("#notice").textContent = text;
  $("#notice").classList.add("visible");
  clearTimeout(notify.timer);
  notify.timer = setTimeout(
    () => $("#notice").classList.remove("visible"),
    5500,
  );
}
async function request(
  path,
  { body, agent, method = body === undefined ? "GET" : "POST", key } = {},
) {
  const headers = { "X-North-UI": "1" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (agent) headers["X-North-Agent"] = agent;
  const payload = body === undefined ? undefined : JSON.stringify(body);
  const slot =
    "north.retry." + path + ":" + (agent || "") + ":" + (payload || "");
  if (method === "POST" && path !== "/ui/session") {
    key = key || sessionStorage.getItem(slot) || crypto.randomUUID();
    sessionStorage.setItem(slot, key);
    headers["Idempotency-Key"] = key;
  }
  let response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: payload,
      credentials: "same-origin",
      signal: AbortSignal.timeout(20000),
    });
  } catch (e) {
    throw Error(
      "Связь прервалась. Повторите действие: запрос сохранён, повторного списания не будет.",
    );
  }
  const data = await response.json();
  if (response.ok) {
    sessionStorage.removeItem(slot);
    return data;
  }
  if (response.status === 401) {
    login();
    throw Error("Войдите в демо, чтобы продолжить.");
  }
  if (response.status < 500 && response.status !== 429)
    sessionStorage.removeItem(slot);
  const messages = {
    400: "Проверьте данные формы.",
    403: "Действие недоступно: проверьте доступ агента и условия поручения.",
    404: "Запись не найдена.",
    409: "Состояние изменилось. Обновите страницу и проверьте операцию.",
    429: "Слишком много запросов. Попробуйте через минуту.",
    503: "Backend временно недоступен. Попробуйте ещё раз.",
  };
  throw Error(
    messages[response.status] ||
      `Не удалось выполнить действие (${response.status}).`,
  );
}
const post = (path, body = {}, agent) =>
  request(path.startsWith("/ui/") ? path : "/ui/api/v1/" + path, {
    body,
    agent,
  });
async function refresh() {
  const data = await request("/ui/workspace");
  if (authenticated) state = data;
}
function savePending() {
  if (pending)
    sessionStorage.setItem(
      "north.purchase." + state.owner,
      JSON.stringify(pending),
    );
  else sessionStorage.removeItem("north.purchase." + state.owner);
}
function nav(section) {
  const items = [
    ["mandates", "layers", "Поручения"],
    ["agents", "user-round", "Агенты"],
    ["operations", "arrow-left-right", "Операции"],
  ];
  return items
    .map(
      ([id, i, name]) =>
        `<a href="#/${id}" ${section === id ? 'class="active" aria-current="page"' : ""}>${icon(i)}<span>${name}</span></a>`,
    )
    .join("");
}
function shell(body, section = "mandates", crumb = "Поручения") {
  app.innerHTML = `<aside class="sidebar"><a href="#/mandates" class="brand">NORTH</a><span class="demo">Демо</span><nav class="nav" aria-label="Основная навигация">${nav(section)}</nav><div class="sidebar-footer"><button class="help" data-action="help">${icon("circle-help")} Помощь</button><div class="profile"><span class="avatar">ЛК</span><div class="identity"><strong>${esc(state.owner)}</strong><p class="small">Личный счёт · демо</p></div></div></div></aside><div class="workspace"><header class="topbar"><div class="mobile-brand"><a href="#/mandates" class="brand">NORTH</a><span class="demo">Демо</span></div><span class="breadcrumb">Личный счёт / ${esc(crumb)}</span><div class="row"><span class="today">${new Date().toLocaleDateString("ru-RU", { day: "numeric", month: "long", year: "numeric" })}</span><button data-action="logout">Выйти</button></div></header><main class="content" id="main" tabindex="-1">${body}<p class="footnote muted">Демонстрационный режим. Реальные деньги не списываются, товары не заказываются.</p></main></div><nav class="bottom-nav" aria-label="Навигация на телефоне">${nav(section)}</nav>`;
}
function head(title, subtitle, action = "") {
  return `<div class="page-head"><div><h1>${title}</h1><p>${subtitle}</p></div>${action}</div>`;
}
const guard = () =>
  `<div class="guard">${icon("shield-check")}<h4>Условия проверяются перед оплатой</h4><p>Если сумма, товар или поставщик изменятся, NORTH остановит покупку.</p></div>`;
const back = () => '<a class="back" href="#/mandates">← Все поручения</a>';
function summary() {
  const active = state.mandates.filter((m) => m.state === "ACTIVE");
  return `<aside class="summary"><div class="dark-card"><p>Лимиты активных поручений</p><div class="money">${money(active.reduce((sum, m) => sum + m.terms.max_amount, 0))}</div><p>Лимит не списывается. Оплата — только после проверки условий.</p></div><h3>Сегодня</h3><dl><div class="kv"><dt>Активных поручений</dt><dd>${active.length}</dd></div><div class="kv"><dt>Подключено агентов</dt><dd>${state.agents.filter((a) => a.status === "ACTIVE").length}</dd></div><div class="kv"><dt>Оплаченных покупок</dt><dd>${state.payments.filter((p) => p.state === "SUCCEEDED").length}</dd></div></dl>${guard()}</aside>`;
}
function mandates() {
  const list = state.mandates.filter((m) =>
    tab === "active"
      ? ["ACTIVE", "DRAFT"].includes(m.state)
      : !["ACTIVE", "DRAFT"].includes(m.state),
  );
  shell(
    head(
      "Поручения",
      "Агенты ищут предложения. Вы задаёте условия покупки.",
      `<a class="btn primary" href="#/new">${icon("plus")}Создать поручение</a>`,
    ) +
      `<div class="grid"><section><div class="tabs" role="group" aria-label="Статус поручений"><button data-action="tab" data-value="active" class="${tab === "active" ? "active" : ""}">Активные · ${state.mandates.filter((m) => ["ACTIVE", "DRAFT"].includes(m.state)).length}</button><button data-action="tab" data-value="done" class="${tab === "done" ? "active" : ""}">Завершённые</button></div>${list.length ? list.map((m, i) => mandateCard(m, i === 0)).join("") : `<div class="empty">${icon("layers")}<h2>${tab === "active" ? "Ваше первое поручение" : "Пока нет завершённых поручений"}</h2><p>${tab === "active" ? "Укажите товар, лимит и разрешённых поставщиков. Агент сможет купить только в этих пределах." : "Здесь появятся выполненные, отозванные и истёкшие поручения."}</p>${tab === "active" ? '<a class="btn primary" href="#/new">Создать поручение</a>' : ""}</div>`}</section>${summary()}</div>`,
  );
}
function mandateCard(m, hero) {
  const t = m.terms;
  const proposal = m.state === "ACTIVE" && homeOffers.find(o=>o.transaction.mandate_id === t.id && o.policy.decision === "ASK_USER");
  return hero
    ? `<article class="card hero"><div class="row between">${badge(proposal ? "ASK_USER" : m.state)}<span class="small muted">№ ${esc(t.id.slice(-6))}</span></div><h2>${esc(t.purpose)}</h2><p>${esc(t.product)} · ${t.condition === "new" ? "Новый" : "Б/у"}</p><div class="budget"><p class="small">Лимит покупки, с доставкой</p><div class="money">${money(t.max_amount)}</div></div><div class="divider"></div><div class="row between"><span>Агент «Закупки»</span><span class="expiry">Купить до ${date(t.expires_at)}</span></div>${proposal ? `<div class="callout amber"><strong>${esc(merchant(proposal.offer.merchant_id))} · ${money(proposal.offer.amount)}</strong><p>Новый поставщик. Без вашего подтверждения покупка не состоится.</p><a href="#/mandate/${esc(t.id)}">Посмотреть предложение →</a></div>` : m.state === "ACTIVE" ? `<div class="callout blue"><strong>Поручение готово к поиску</strong><p>Проверим предложения по вашему лимиту и списку поставщиков.</p><a href="#/mandate/${esc(t.id)}">Посмотреть предложения →</a></div>` : ""}<a class="link-button" href="#/mandate/${esc(t.id)}">Детали поручения →</a></article>`
    : `<article class="list-card"><div class="row between"><h3><a href="#/mandate/${esc(t.id)}">${esc(t.purpose)}</a></h3><strong>${money(t.max_amount)}</strong></div><p>${esc(t.product)} · агент «Закупки»</p><div class="row wrap">${badge(m.state)}<span class="expiry">До ${date(t.expires_at)}</span></div></article>`;
}
function newMandate() {
  const agents = state.agents.filter((a) => a.status === "ACTIVE");
  shell(
    back() +
      head(
        "Новое поручение",
        "Вы задаёте границы. Агент ищет подходящую покупку.",
      ) +
      `<form id="mandate-form"><div class="grid form-grid"><div class="card"><section class="form-section"><h3>Что нужно купить</h3><label class="field"><span>Название поручения</span><input name="purpose" maxlength="120" required value="Купить монитор"></label><label class="field"><span>Товар из демокаталога</span><select name="product"><option>Dell UltraSharp U2723QE</option></select><small>27″ · 4K · новый. В sandbox подключены три предложения.</small></label><label class="field"><span>Лимит покупки, ₽</span><input name="budget" type="number" min="1" max="10000000" step="0.01" inputmode="decimal" required value="85000"><small>Включая стоимость товара, комиссии и доставку.</small></label></section><section class="form-section"><h3>Кому поручить</h3>${agents.length ? `<label class="field"><span>Агент</span><select name="agent">${agents.map((a) => `<option value="${esc(a.id)}">Закупки · ${esc(a.id.slice(-6))}</option>`).join("")}</select></label>` : `<p>Подключите агента для выполнения покупки.</p><button type="button" class="btn" data-action="register">${icon("shopping-bag")}Подключить агента «Закупки»</button>`}<p class="small">Агент не получает доступ к счёту. Ему разрешена только покупка по условиям поручения.</p></section><section class="form-section"><h3>Поставщики</h3><label class="check"><input type="checkbox" name="merchants" value="dns" checked><span><strong>DNS</strong><small>Проверенный поставщик</small></span></label><label class="check"><input type="checkbox" name="merchants" value="citilink" checked><span><strong>Ситилинк</strong><small>Проверенный поставщик</small></span></label><div class="divider"></div><label class="check"><input type="checkbox" name="approval" checked><span><strong>Нового поставщика подтверждаю лично</strong><small>Агент предложит вариант и дождётся вашего решения.</small></span></label></section><section class="form-section"><h3>Срок и ограничения</h3><label class="field"><span>Поручение действует до</span><input name="expiry" type="date" required min="${new Date(Date.now() + 86400000).toISOString().slice(0, 10)}" value="${new Date(Date.now() + 3 * 86400000).toISOString().slice(0, 10)}"></label><div class="callout blue"><strong>Одна покупка — одно поручение</strong><p>После покупки разрешение перестанет действовать. Повторно потратить лимит нельзя.</p></div></section><p class="error" id="form-error" role="alert"></p><div class="form-actions"><button class="btn primary" type="submit" ${agents.length ? "" : "disabled"}>Создать и разрешить поиск</button><button class="btn" name="draft" value="1" type="submit" ${agents.length ? "" : "disabled"}>Сохранить черновик</button></div></div><aside class="summary"><h3>Ваше поручение</h3><dl><div class="kv"><dt>Покупка</dt><dd id="preview-purpose">Купить монитор</dd></div><div class="kv"><dt>Лимит</dt><dd id="preview-budget">85 000 ₽</dd></div><div class="kv"><dt>Количество покупок</dt><dd>Одна</dd></div><div class="kv"><dt>Новый поставщик</dt><dd id="preview-approval">С подтверждением</dd></div></dl>${guard()}<p class="footnote">Это тестовая покупка. Адрес доставки не требуется.</p></aside></div></form>`,
  );
}
function termsPanel(m) {
  const t = m.terms;
  return `<aside class="summary"><h3>Условия поручения</h3><dl><div class="kv"><dt>Агент</dt><dd>Закупки · ${esc(t.agent_id.slice(-6))}</dd></div><div class="kv"><dt>Поставщики</dt><dd>${t.merchants.map(merchant).map(esc).join(", ") || "Любой"}</dd></div><div class="kv"><dt>Новый поставщик</dt><dd>${t.allow_merchant_approval ? "С подтверждением" : "Не разрешён"}</dd></div><div class="kv"><dt>Купить до</dt><dd>${date(t.expires_at)}</dd></div><div class="kv"><dt>Покупок</dt><dd>${m.consumed_uses} из ${t.max_uses}</dd></div></dl>${guard()}${["ACTIVE", "DRAFT"].includes(m.state) ? `<button class="btn danger block" data-action="revoke" data-id="${esc(t.id)}">Отозвать поручение</button>` : ""}</aside>`;
}
async function detail(id, version) {
  const m = state.mandates.find((m) => m.terms.id === id);
  if (!m) {
    shell(
      back() +
        head("Поручение не найдено", "Вернитесь к списку и обновите страницу."),
    );
    return;
  }
  offers = await request("/ui/offers?mandate=" + encodeURIComponent(id));
  if (version !== routeVersion) return;
  const t = m.terms;
  shell(
    back() +
      head(esc(t.purpose), esc(t.product) + " · 27″ · 4K") +
      `<div class="grid"><section><div class="card"><div class="row between">${badge(m.state)}<span class="small muted">№ ${esc(id.slice(-6))}</span></div><div class="budget"><p>Лимит покупки, с доставкой</p><div class="money">${money(t.max_amount)}</div></div><p>Оплата только после проверки всех условий.</p>${m.state === "DRAFT" ? `<button class="btn primary" data-action="approve-draft" data-id="${esc(id)}">Подтвердить поручение</button>` : ""}</div><h2 class="section-head">Предложения</h2><div class="offers">${offers.length ? offers.map((o, i) => offerCard(o, i)).join("") : '<div class="empty"><h3>Предложений пока нет</h3><p>В демокаталоге нет этого товара.</p></div>'}</div></section>${termsPanel(m)}</div>`,
  );
}
function offerCard(item, i) {
  const o = item.offer,
    d = item.policy.decision;
  return `<article class="offer ${d === "ALLOW" ? "recommended" : ""}"><div class="offer-head"><h3>${esc(merchant(o.merchant_id))}</h3>${badge(d)}</div><div class="money">${money(o.amount)}</div><p>${esc(o.product)} · новый</p><p class="small">${o.verified ? "Поставщик в проверенном каталоге" : "Поставщик не проверен"} · комиссия ${money(o.fees)} · доставка ${money(o.shipping)}</p>${d === "ASK_USER" ? '<div class="callout amber"><strong>Новый поставщик</strong><p>Не входит в ваш список. Без подтверждения покупка не состоится.</p></div>' : ""}${
    d === "DENY"
      ? `<p class="error">${item.policy.rules
          .filter((r) => !r.passed)
          .map((r) =>
            esc(
              ruleFailures[r.code] ||
                "Не выполнено условие: " + (ruleNames[r.code] || r.code),
            ),
          )
          .join(" · ")}</p>`
      : ""
  }<button class="btn ${d === "ALLOW" ? "primary" : ""}" data-action="offer" data-index="${i}">${d === "ALLOW" ? "Выбрать предложение" : d === "ASK_USER" ? "Посмотреть предложение" : "Посмотреть причину"}</button></article>`;
}
function purchaseView() {
  if (!pending) {
    location.hash = "#/mandates";
    return;
  }
  const { item, authorization: auth } = pending,
    o = item.offer,
    d = auth?.policy.decision || item.policy.decision;
  const m = state.mandates.find(
    (m) => m.terms.id === item.transaction.mandate_id,
  );
  if (d === "DENY") {
    blocked();
    return;
  }
  shell(
    `<a class="back" href="#/mandate/${esc(item.transaction.mandate_id)}">← К поручению</a>` +
      head(
        d === "ASK_USER" ? "Подтвердите покупку" : "Проверьте покупку",
        d === "ASK_USER"
          ? "Агент нашёл предложение у нового поставщика. Решение за вами."
          : "Агент купит товар на указанных условиях.",
      ) +
      `<div class="grid form-grid"><section class="card"><span class="muted">Сумма покупки</span><div class="money">${money(o.amount)}</div><div class="product"><div class="product-icon">${icon("monitor")}</div><div><h3>${esc(o.product)}</h3><p>27″ · 4K · новый</p></div></div><dl><div class="kv"><dt>Поставщик</dt><dd>${esc(merchant(o.merchant_id))}</dd></div><div class="kv"><dt>Агент</dt><dd>Закупки</dd></div><div class="kv"><dt>Товар</dt><dd>${money(o.unit_amount)}</dd></div><div class="kv"><dt>Доставка и комиссии</dt><dd>${money(o.shipping + o.fees)}</dd></div><div class="kv"><dt>Ваш лимит</dt><dd>${money(m?.terms.max_amount)}</dd></div></dl><div class="form-actions"><button class="btn primary" data-action="purchase">${d === "ASK_USER" ? "Подтвердить и купить за" : "Купить за"} ${money(o.amount)}</button><a class="btn" href="#/mandate/${esc(item.transaction.mandate_id)}">Вернуться к предложениям</a></div><p class="footnote">Подтверждение действует только для этой покупки. Поставщик, товар и сумма зафиксированы.</p></section><aside class="summary">${d === "ASK_USER" ? `<div class="callout amber"><div class="row">${icon("shield-alert")}<strong>Поставщик вне вашего списка</strong></div><p>${esc(merchant(o.merchant_id))} не указан в поручении. После вашего согласия агент сможет выполнить эту покупку.</p></div>` : ""}<h3>Что проверено</h3><ul class="rules">${item.policy.rules
        .filter((r) =>
          [
            "PRODUCT_MATCH",
            "AMOUNT_WITHIN_LIMIT",
            "OFFER_AUTHENTIC",
            "USAGE_AVAILABLE",
            "MERCHANT_ALLOWED",
          ].includes(r.code),
        )
        .map(
          (r) =>
            `<li class="${r.passed ? "" : "rule-fail"}">${icon(r.passed ? "check" : "triangle-alert")}<span>${esc(r.passed ? ruleNames[r.code] : ruleFailures[r.code] || ruleNames[r.code])}</span></li>`,
        )
        .join("")}</ul>${guard()}</aside></div>`,
  );
}
function blocked() {
  const item = pending.item;
  const policy = pending.authorization?.policy || item.policy;
  shell(
    back() +
      `<section class="card result-card"><div class="result-icon">${icon("shield-alert")}</div>${badge("DENY")}<h1 class="section-head">Покупка заблокирована</h1><p class="muted">Условия поручения не соблюдены. Деньги не списаны.</p><div class="money">${money(item.offer.amount)}</div><p>${esc(item.offer.product)} · ${esc(merchant(item.offer.merchant_id))}</p><div class="callout red section-head"><h3>Почему остановили покупку</h3><ul class="rules">${policy.rules
        .filter((r) => !r.passed)
        .map(
          (r) =>
            `<li>${icon("triangle-alert")}${esc(ruleFailures[r.code] || "Не выполнено условие: " + (ruleNames[r.code] || r.code))}</li>`,
        )
        .join(
          "",
        )}</ul></div><a class="btn primary" href="#/mandate/${esc(item.transaction.mandate_id)}">Выбрать другое предложение</a>${guard()}</section>`,
  );
}
function paymentView(id) {
  const p = state.payments.find((p) => p.id === id);
  if (!p) {
    shell(
      head("Проверяем операцию", "Запрашиваем актуальный статус у сервера.") +
        '<button class="btn" data-action="refresh">Обновить статус</button>',
      "operations",
      "Операции",
    );
    return;
  }
  const done = p.state === "SUCCEEDED",
    waiting = ["PENDING", "SUBMITTED", "UNKNOWN"].includes(p.state);
  shell(
    `<section class="card result-card"><div class="result-icon">${icon(done ? "check" : waiting ? "clock-3" : "shield-alert")}</div>${badge(p.state)}<h1 class="section-head">${done ? "Покупка оплачена" : waiting ? "Уточняем статус оплаты" : "Покупка не выполнена"}</h1><p class="muted">${done ? "Агент выполнил покупку в пределах разрешения." : waiting ? "Покупка уже передана на оплату. Повторять её не нужно." : "Проверьте историю операции перед новой попыткой."}</p><div class="money">${money(p.transaction.amount)}</div><div class="product"><div class="product-icon">${icon("monitor")}</div><div><h3>${esc(p.transaction.product)}</h3><p>${esc(merchant(p.transaction.merchant_id))} · агент «Закупки»</p></div></div><dl><div class="kv"><dt>Создана</dt><dd>${date(p.created_at)}</dd></div><div class="kv"><dt>Статус</dt><dd>${esc(labels[p.state] || p.state)}</dd></div><div class="kv"><dt>Номер операции</dt><dd class="receipt-id">${esc(p.id)}</dd></div></dl>${waiting ? '<div class="callout amber section-head"><strong>Не создавайте повторную покупку</strong><p>NORTH сам сверит ответ платёжного провайдера. Статус обновляется автоматически.</p></div>' : '<div class="callout blue section-head"><strong>Одноразовое разрешение использовано</strong><p>Для следующей покупки потребуется новое поручение.</p></div>'}<div class="form-actions"><a href="#/operations" class="btn primary">Открыть операции</a>${done ? `<button class="btn" data-action="receipt" data-id="${esc(id)}">Скачать сведения</button>` : '<button class="btn" data-action="refresh">Обновить статус</button>'}</div><p class="footnote">Демонстрационная операция, не банковский или кассовый чек.</p></section>`,
    "operations",
    "Операции",
  );
  if (waiting) poll = setTimeout(() => route(false), 2500);
}
function agents() {
  const a = state.agents.find((a) => a.id === selectedAgent) || state.agents[0];
  selectedAgent = a?.id || "";
  shell(
    head(
      "Агенты",
      "Вы решаете, что агент может делать от вашего имени.",
      `<button class="btn primary" data-action="register">${icon("plus")}Подключить агента</button>`,
    ) +
      `<div class="stats"><div class="stat"><p>Подключено</p><strong>${state.agents.length}</strong></div><div class="stat"><p>Активных</p><strong>${state.agents.filter((a) => a.status === "ACTIVE").length}</strong></div><div class="stat"><p>Активных поручений</p><strong>${state.mandates.filter((m) => m.state === "ACTIVE").length}</strong></div></div><div class="grid form-grid"><section>${state.agents.length ? state.agents.map((ag) => `<button class="agent-row ${ag.id === a.id ? "selected" : ""}" data-action="select-agent" data-id="${esc(ag.id)}"><span class="agent-symbol">${icon("shopping-bag")}</span><span><h3>Закупки</h3><p>Sandbox · ${esc(ag.id.slice(-6))}</p></span>${badge(ag.status)}</button>`).join("") : '<div class="empty"><h2>Агенты ещё не подключены</h2><p>Подключите агента и создайте для него первое поручение.</p></div>'}</section><aside class="card">${
        a
          ? `<h2>Агент «Закупки»</h2>${badge(a.status)}<p class="section-head">Покупает товары по вашим поручениям. Работает только с демокаталогом.</p><h3>Границы доступа</h3><ul class="rules"><li>${icon("check")}Только разрешённые покупки</li><li>${icon("check")}Проверка суммы и поставщика</li><li>${icon("check")}Без доступа к вашему счёту</li></ul><h3>Поручения агента</h3>${
              state.mandates
                .filter((m) => m.terms.agent_id === a.id)
                .map(
                  (m) =>
                    `<div class="list-card"><a href="#/mandate/${esc(m.terms.id)}">${esc(m.terms.purpose)}</a><p>${money(m.terms.max_amount)} · ${esc(labels[m.state])}</p></div>`,
                )
                .join("") || '<p class="section-head">Пока нет поручений</p>'
            }${a.status === "ACTIVE" ? `<button class="btn danger block section-head" data-action="revoke-agent" data-id="${esc(a.id)}">Отозвать доступ</button>` : ""}`
          : '<h3>Управление доступом</h3><p class="section-head">Вы сможете отозвать доступ агента в любой момент.</p>'
      }</aside></div>`,
    "agents",
    "Агенты",
  );
}
function operations() {
  const paid = state.payments.filter((p) => p.state === "SUCCEEDED"),
    p =
      state.payments.find((p) => p.id === selectedPayment) || state.payments[0];
  selectedPayment = p?.id || "";
  shell(
    head(
      "Операции",
      "Покупки агентов и история ваших решений.",
      `<button class="btn" data-action="export">Скачать историю</button>`,
    ) +
      `<div class="stats"><div class="stat"><p>Оплачено в демо</p><strong>${money(paid.reduce((s, p) => s + p.transaction.amount, 0))}</strong></div><div class="stat"><p>Покупок оплачено</p><strong>${paid.length}</strong></div><div class="stat"><p>Ожидают результата</p><strong>${state.payments.filter((p) => ["PENDING", "UNKNOWN", "SUBMITTED"].includes(p.state)).length}</strong></div></div><div class="grid form-grid"><section><h2 class="section-head">Покупки</h2>${state.payments.map((t) => `<button class="transaction ${t.id === selectedPayment ? "selected" : ""}" data-action="select-payment" data-id="${esc(t.id)}"><span><strong>${esc(merchant(t.transaction.merchant_id))}</strong><p>${esc(t.transaction.product)}</p><p>${date(t.created_at)}</p></span><span class="amount">${money(t.transaction.amount)}<br>${badge(t.state)}</span></button>`).join("") || '<div class="empty"><h3>Покупок пока нет</h3><p>После первой оплаты здесь появятся сумма, поставщик и результат.</p></div>'}<h2 class="section-head">История решений</h2>${
        state.events
          .filter(
            (e) =>
              !e.kind?.includes("authenticated") &&
              !e.kind?.includes("credential"),
          )
          .slice(0, 40)
          .map(
            (e) =>
              `<div class="audit-row"><div><strong>${esc(eventNames[e.kind] || e.kind)}</strong><p>№ ${esc(e.subject?.slice(-8))}</p></div><time>${date(e.at)}</time></div>`,
          )
          .join("") || "<p>Событий пока нет.</p>"
      }</section><aside class="card"><h2>Детали операции</h2>${p ? `${badge(p.state)}<div class="budget"><div class="money">${money(p.transaction.amount)}</div></div><dl><div class="kv"><dt>Поставщик</dt><dd>${esc(merchant(p.transaction.merchant_id))}</dd></div><div class="kv"><dt>Товар</dt><dd>${esc(p.transaction.product)}</dd></div><div class="kv"><dt>Дата</dt><dd>${date(p.created_at)}</dd></div><div class="kv"><dt>Номер</dt><dd class="receipt-id">${esc(p.id)}</dd></div></dl><div class="form-actions"><a class="btn primary" href="#/payment/${esc(p.id)}">Статус покупки</a><button class="btn" data-action="receipt" data-id="${esc(p.id)}">Скачать сведения</button></div>` : "<p>Выберите покупку, чтобы увидеть подробности.</p>"}${guard()}</aside></div>`,
    "operations",
    "Операции",
  );
}
async function route(reload = true) {
  clearTimeout(poll);
  const version = ++routeVersion;
  try {
    if (reload || location.hash.startsWith("#/payment")) await refresh();
    if (version !== routeVersion) return;
    const [page = "mandates", id] = location.hash
      .replace(/^#\/?/, "")
      .split("/");
    document.title =
      "NORTH — " +
      ({ agents: "агенты", operations: "операции", new: "новое поручение" }[
        page
      ] || "поручения");
    if (page === "new") newMandate();
    else if (page === "mandate") await detail(id, version);
    else if (page === "purchase") purchaseView();
    else if (page === "payment") paymentView(id);
    else if (page === "agents") agents();
    else if (page === "operations") operations();
    else {
 const first = state.mandates.find(m=>m.state === "ACTIVE");
 homeOffers = first ? await request("/ui/offers?mandate="+encodeURIComponent(first.terms.id)) : [];
 if(version !== routeVersion) return;
 mandates();
 }
    if (reload) window.scrollTo(0, 0);
  } catch (e) {
    if ($("#main")) {
      notify(e.message);
    } else if (!$("#login-form")) {
      app.innerHTML =
        '<main class="login"><h1>NORTH</h1><p class="error">' +
        esc(e.message) +
        '</p><button class="btn" data-action="refresh">Повторить</button></main>';
    }
  }
}
function login() {
  authenticated = false;
  routeVersion++;
  state.owner = "";
  clearTimeout(poll);
  app.innerHTML = `<main class="login" id="main"><h1>NORTH</h1><span class="demo">Демонстрационный режим</span><h2>Ваши условия.<br>Действия агента.</h2><p>Создавайте поручения, проверяйте предложения и управляйте покупками в одном месте.</p><form id="login-form"><label class="field"><span>Ключ доступа к демо</span><input type="password" name="token" required autocomplete="current-password" placeholder="Введите ключ владельца"></label><p class="error" id="login-error" role="alert"></p><button class="btn primary block" type="submit">Войти в NORTH</button></form><div class="callout"><strong>Где взять ключ?</strong><p>Используйте NORTH_OWNER_TOKEN из локального файла .env, созданного при запуске sandbox.</p><p>Реальные деньги не списываются.</p></div></main>`;
}
function confirmAction(title, text, action) {
  const d = $("#dialog");
  d.innerHTML = `<h2>${esc(title)}</h2><p>${esc(text)}</p><div class="form-actions"><button class="btn" id="cancel-dialog">Отмена</button><button class="btn danger" id="confirm-dialog">Подтвердить</button></div>`;
  d.showModal();
  $("#cancel-dialog").onclick = () => d.close();
  $("#confirm-dialog").onclick = async () => {
    d.close();
    await run(action);
  };
}
async function run(fn) {
  if (busy) return;
  busy = true;
  document.querySelectorAll("button").forEach((b) => {
    b.dataset.wasDisabled = b.disabled ? "1" : "0";
    b.disabled = true;
  });
  try {
    await fn();
  } catch (e) {
    notify(e.message);
  } finally {
    busy = false;
    document.querySelectorAll("button[data-was-disabled]").forEach((b) => {
      b.disabled = b.dataset.wasDisabled === "1";
      delete b.dataset.wasDisabled;
    });
  }
}
async function selectOffer(index) {
  const item = offers[index];
  pending = { item };
  if (item.policy.decision !== "ALLOW") {
    pending.authorization = await post(
      "/ui/agent/authorizations",
      { transaction: item.transaction },
      item.transaction.agent_id,
    );
  }
  savePending();
  location.hash = "#/purchase";
}
async function purchase() {
  const p = pending;
  if (!p) return;
  const t = p.item.transaction;
  let auth = p.authorization;
  if (auth?.policy.decision === "ASK_USER") {
    await post("challenges/approve", {
      agent_id: t.agent_id,
      mandate_id: t.mandate_id,
      challenge_id: auth.challenge_id,
      transaction_hash: p.item.transaction_hash,
    });
    p.approved = true;
    savePending();
    auth = null;
  }
  if (!auth || (p.approved && !auth.grant)) {
    auth = await post(
      "/ui/agent/authorizations",
      { transaction: t },
      t.agent_id,
    );
    p.authorization = auth;
    savePending();
  }
  if (auth.policy.decision !== "ALLOW") {
    purchaseView();
    return;
  }
  if (auth.grant.claims.expires_at <= Date.now() / 1000) {
    pending.authorization = null;
    savePending();
    throw Error(
      "Срок разрешения истёк. Откройте предложения и выберите покупку заново.",
    );
  }
  const result = await post(
    "/ui/agent/payments",
    { grant: auth.grant, transaction: t },
    t.agent_id,
  );
  pending = null;
  savePending();
  location.hash = "#/payment/" + result.payment_id;
}
function download(name, data) {
  const a = document.createElement("a");
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
  );
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
app.addEventListener("click", (e) => {
  const b = e.target.closest("[data-action]");
  if (!b) return;
  const action = b.dataset.action,
    id = b.dataset.id;
  if (action === "revoke") {
    const m = state.mandates.find((m) => m.terms.id === id);
    confirmAction(
      "Отозвать поручение?",
      "Агент больше не сможет совершить по нему новую покупку. Уже отправленная оплата может завершиться.",
      async () => {
        await post("mandates/revoke", {
          agent_id: m.terms.agent_id,
          mandate_id: id,
        });
        await route();
        notify("Поручение отозвано");
      },
    );
    return;
  }
  if (action === "revoke-agent") {
    confirmAction(
      "Отозвать доступ агента?",
      "Новые покупки этого агента будут заблокированы. Уже отправленные оплаты сохранят свой статус.",
      async () => {
        await post("agents/revoke", { agent_id: id });
        await route();
        notify("Доступ отозван");
      },
    );
    return;
  }
  run(async () => {
    switch (action) {
      case "tab":
        tab = b.dataset.value;
        mandates();
        break;
      case "register":
        await post("agents");
        await route();
        notify("Агент «Закупки» подключён");
        break;
      case "offer":
        await selectOffer(Number(b.dataset.index));
        break;
      case "purchase":
        await purchase();
        break;
      case "approve-draft": {
        const m = state.mandates.find((m) => m.terms.id === id);
        await post("mandates/approve", {
          agent_id: m.terms.agent_id,
          mandate_id: id,
          digest: state.digests[id],
        });
        await route();
        break;
      }
      case "select-agent":
        selectedAgent = id;
        agents();
        break;
      case "select-payment":
        selectedPayment = id;
        operations();
        break;
      case "refresh":
        if (state.owner) await route();
        else await boot();
        break;
      case "logout":
        await request("/ui/session", { method: "DELETE" });
        pending = null;
        for (const k of Object.keys(sessionStorage))
          if (k.startsWith("north.")) sessionStorage.removeItem(k);
        login();
        break;
      case "receipt":
        download("north-operation-" + id.slice(-8) + ".json", {
          demo: true,
          not_a_fiscal_receipt: true,
          payment: state.payments.find((p) => p.id === id),
        });
        break;
      case "export":
        download("north-history.json", {
          demo: true,
          payments: state.payments,
          events: state.events,
        });
        break;
      case "help": {
        const d = $("#dialog");
        d.innerHTML =
          '<h2>Как работает NORTH</h2><p>Создайте поручение: товар, лимит, поставщики и срок. Выберите предложение агента. NORTH проверит условия перед оплатой.</p><p>Для нового поставщика потребуется ваше согласие. Покупка дороже лимита будет заблокирована.</p><p>В этом демо нет реального счёта или заказа товаров.</p><form method="dialog"><button class="btn primary block">Понятно</button></form>';
        d.showModal();
        break;
      }
    }
  });
});
app.addEventListener("input", (e) => {
  const form = e.target.closest("#mandate-form");
  if (!form) return;
  const f = new FormData(form);
  $("#preview-purpose").textContent = f.get("purpose") || "Поручение";
  $("#preview-budget").textContent = money(
    Math.round(Number(f.get("budget")) * 100),
  );
  $("#preview-approval").textContent = f.get("approval")
    ? "С подтверждением"
    : "Не разрешён";
});
app.addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target,
    submitter = e.submitter;
  if (form.id === "login-form") {
    const token = new FormData(form).get("token");
    await run(async () => {
      try {
        await request("/ui/session", { body: { token } });
        form.reset();
        await boot();
      } catch (error) {
        if ($("#login-error"))
          $("#login-error").textContent =
            "Не удалось войти. Проверьте ключ доступа и доступность сервера.";
      }
    });
    return;
  }
  if (form.id !== "mandate-form") return;
  const f = new FormData(form);
  const merchants = f.getAll("merchants");
  if (!merchants.length) {
    $("#form-error").textContent = "Выберите хотя бы одного поставщика.";
    return;
  }
  const budget = Math.round(Number(f.get("budget")) * 100);
  if (!Number.isSafeInteger(budget) || budget <= 0) {
    $("#form-error").textContent = "Укажите корректный лимит.";
    return;
  }
  await run(async () => {
    const terms = {
      agent_id: f.get("agent"),
      action: "purchase",
      purpose: f.get("purpose").trim(),
      product: f.get("product"),
      category: "electronics",
      condition: "new",
      max_amount: budget,
      currency: "RUB",
      merchants,
      require_verified: true,
      allow_risk_approval: false,
      allow_merchant_approval: !!f.get("approval"),
      max_risk: 0,
      max_uses: 1,
      expires_at: Math.floor(
        new Date(f.get("expiry") + "T23:59:59").getTime() / 1000,
      ),
    };
    try {
      const draft = await post("mandates", { terms });
      if (submitter?.name !== "draft") {
        try { await post("mandates/approve", {
          agent_id: terms.agent_id,
          mandate_id: draft.mandate_id,
          digest: draft.digest,
        }); } catch (error) { notify("Черновик сохранён. " + error.message); }
      }
      location.hash = "#/mandate/" + draft.mandate_id;
    } catch (error) {
      $("#form-error").textContent = error.message;
    }
  });
});
window.addEventListener("hashchange", () => {
  if (state.owner) route();
});
async function boot() {
  try {
    const session = await request("/ui/session");
    authenticated = true;
    state.owner = session.owner;
    try {
      pending = JSON.parse(
        sessionStorage.getItem("north.purchase." + state.owner) || "null",
      );
    } catch {
      pending = null;
    }
    await route();
  } catch (e) {
    if (!$("#login-form")) login();
  }
}
boot();
