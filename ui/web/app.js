/* ============================================================
   Email Validator Pro — логика страницы.

   Со стороны питона окно выглядит как обычный HTTP-клиент: страница
   опрашивает /api/state и перерисовывает то, что изменилось. Опрос, а не
   постоянное соединение, выбран сознательно: прогон длится часами, а
   переподключение после разрыва в опросе стоит один пропущенный тик.

   Токен выдаётся при загрузке и уходит заголовком в каждый запрос.
   ============================================================ */

const TOKEN = document.body.dataset.token;
const $  = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

async function api(method, payload = {}) {
  const res = await fetch(`/api/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Token": TOKEN },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`${method}: ${res.status}`);
  return res.json();
}

/* ── мелкие помощники ─────────────────────────────────────── */

let toastTimer = null;
function toast(text, kind = "") {
  const el = $("#toast");
  el.textContent = text;
  el.className = "toast" + (kind ? ` toast--${kind}` : "");
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 3200);
}

const nf = new Intl.NumberFormat("ru-RU");
const num = (value) => nf.format(Number(value) || 0);

/* Ставим текст только когда он изменился: перерисовка узла заставляет
   браузер пересчитывать раскладку, а тик идёт четыре раза в секунду. */
function setText(el, value) {
  const next = String(value);
  if (el.textContent !== next) el.textContent = next;
}

/* ============================================================
   Состояние страницы
   ============================================================ */

const ui = {
  tab: "log",
  page: 1,
  groups: ["valid"],
  minScore: 0,
  country: "coverage",
  running: false,
  mode: "validator",
  lastSig: "",          // отпечаток выборки: по нему решаем, перезапрашивать ли
};

/* Сбор адресов держит своё состояние отдельно: два прогона могут идти
   одновременно, и мешать их счётчики в одну кучу нельзя. */
const parser = { tab: "log", page: 1, running: false, total: -1 };

/* ── источники: файлы и вставленный текст ─────────────────── */

const EMPTY_HINT = {
  emails:  "txt или csv · можно перетащить сюда",
  proxies: "socks5, socks4 или http",
  dorks:   "по запросу в строке · можно перетащить сюда",
  pproxy:  "нужны движкам с пометкой Proxies",
};

function renderSources(data) {
  const bind = (prefix, info, dropId, clearId) => {
    setText($(`#${prefix}Title`), info.title);
    const hint = $(`#${prefix}Hint`);
    if (info.count) {
      setText(hint, info.detail);
      $(dropId).classList.add("is-set");
      $(clearId).hidden = false;
    } else {
      setText(hint, EMPTY_HINT[prefix] || "");
      $(dropId).classList.remove("is-set");
      $(clearId).hidden = true;
    }
  };
  bind("emails", data.emails, "#dropEmails", "#clearEmails");
  bind("proxies", data.proxies, "#dropProxies", "#clearProxies");
  bind("dorks", data.dorks, "#dropDorks", "#clearDorks");
  bind("pproxy", data.pproxy, "#dropPproxy", "#clearPproxy");

  const hint = $("#startHint");
  setText(hint, data.hint);
  hint.classList.toggle("is-ready", !!data.ready);
  $("#btnStart").disabled = !data.ready || ui.running;

  const pHint = $("#pStartHint");
  setText(pHint, data.parserHint);
  pHint.classList.toggle("is-ready", !!data.parserReady);
  $("#pBtnStart").disabled = !data.parserReady || parser.running;
}

async function refreshSources() { renderSources(await api("sources")); }

/* ── лог ──────────────────────────────────────────────────── */

const logBox = $("#log");
const MAX_LOG_NODES = 1200;   // столько строк человек всё равно не отмотает

function appendLog(lines) {
  if (!lines || !lines.length) return;
  const atBottom = logBox.scrollTop + logBox.clientHeight >= logBox.scrollHeight - 24;
  const frag = document.createDocumentFragment();
  for (const line of lines) {
    const span = document.createElement("span");
    span.className = `l-${line.tag || "info"}`;
    span.textContent = line.text + "\n";
    frag.appendChild(span);
  }
  logBox.appendChild(frag);
  while (logBox.childNodes.length > MAX_LOG_NODES) logBox.removeChild(logBox.firstChild);
  if (atBottom) logBox.scrollTop = logBox.scrollHeight;
}

/* ── таблица ──────────────────────────────────────────────── */

/* Короткие подписи: колонка вердикта узкая, а длинное слово в ней всё равно
   обрежется многоточием и станет нечитаемым. Полное название и исходный
   статус движка остаются в подсказке по наведению. */
const VERDICT_TEXT = {
  valid: "Годен",
  invalid: "Мёртв",
  spam: "Не слать",
  unknown: "Неясно",
};
const VERDICT_FULL = {
  valid: "Можно слать — доказано, что ящик существует",
  invalid: "Слать нельзя — доказано, что ящика нет",
  spam: "Ловушка или роль-адрес — письмо портит репутацию",
  unknown: "Не доказано — ответа не получили",
};

/* Дата в узкой колонке: год и секунды не помогают решать, а место занимают.
   Полное значение остаётся в подсказке. */
function shortDate(value) {
  const m = String(value || "").match(/^\d{4}-(\d{2})-(\d{2})\s+(\d{2}:\d{2})/);
  return m ? `${m[2]}.${m[1]} ${m[3]}` : (value || "");
}

/* Пол одной буквой: колонка узкая, а «Мужской» в ней превращается в
   «Мужс…» — то же место, но уже нечитаемо. Полное слово в подсказке. */
function shortGender(value) {
  const v = String(value || "").toLowerCase();
  if (v.startsWith("муж")) return "М";
  if (v.startsWith("жен")) return "Ж";
  return value || "";
}

function scoreClass(score) {
  const n = Number(score);
  if (!Number.isFinite(n) || score === "") return "";
  if (n >= 70) return "score--hi";
  if (n >= 40) return "score--mid";
  return "score--low";
}

function renderRows(data) {
  const body = $("#gridBody");
  const empty = $("#gridEmpty");

  if (!data.rows.length) {
    body.replaceChildren();
    empty.hidden = false;
    setText($("#pageLabel"), "Стр. 1 / 1");
    setText($("#pageCount"), "");
    return;
  }
  empty.hidden = true;

  const frag = document.createDocumentFragment();
  for (const row of data.rows) {
    const tr = document.createElement("tr");
    const cells = [
      ["c-email", row.email, row.email],
      ["c-verdict", null, null],
      ["c-score", null, null],
      ["c-prov", row.provider, row.provider],
      ["c-reason", row.reason, row.reason],
      ["c-name", row.name, row.name],
      ["c-gender", shortGender(row.gender), row.gender],
      ["c-country", row.country, row.country],
      ["c-when", shortDate(row.when), row.when],
    ];
    cells.forEach(([cls, text, title], index) => {
      const td = document.createElement("td");
      td.className = cls;
      if (index === 1) {
        const badge = document.createElement("span");
        badge.className = `v v--${row.group}`;
        badge.textContent = VERDICT_TEXT[row.group] || row.status;
        td.title = `${VERDICT_FULL[row.group] || row.status} (${row.status})`;
        td.appendChild(badge);
      } else if (index === 2) {
        const span = document.createElement("span");
        span.className = `score ${scoreClass(row.score)}`;
        span.textContent = row.score === "" ? "—" : row.score;
        td.appendChild(span);
      } else {
        td.textContent = text || "—";
        if (title) td.title = title;
      }
      tr.appendChild(td);
    });
    frag.appendChild(tr);
  }
  body.replaceChildren(frag);

  ui.page = data.page;
  setText($("#pageLabel"), `Стр. ${data.page} / ${data.pages}`);
  setText($("#pageCount"), `${num(data.total)} адресов в выборке`);
  $("#pagePrev").disabled = data.page <= 1;
  $("#pageNext").disabled = data.page >= data.pages;
}

async function refreshRows(force = false) {
  if (ui.tab !== "results") return;
  const sig = [ui.groups.join(","), ui.minScore, ui.page].join("|");
  if (!force && sig === ui.lastSig && !ui.running) return;
  ui.lastSig = sig;
  renderRows(await api("page", {
    groups: ui.groups, minScore: ui.minScore, page: ui.page,
  }));
}

/* ── панель прокси ────────────────────────────────────────── */

function metric(title, value, hint) {
  return `<div class="pmetric"><span>${title}</span><b>${value}</b><small>${hint}</small></div>`;
}

function block(title, hint, rows) {
  if (!rows.length) return "";
  const body = rows.map(([label, value, cls]) =>
    `<div class="prow"><span>${label}</span><b class="${cls || ""}">${value}</b></div>`).join("");
  return `<div class="pblock"><h4>${title}</h4><span class="phint">${hint}</span>${body}</div>`;
}

function renderProxy(summary) {
  const host = $("#proxyBody");
  if (!summary) return;

  const total = summary.total || 0;
  const unique = summary.unique_ips || 0;
  const dupes = summary.duplicates || 0;
  const median = summary.latency_median;

  const fitness = Object.entries(summary.fitness || {}).map(([name, c]) =>
    [name, `годны ${c.ok} · не пустят ${c.no} · не проверено ${c.unknown}`]);

  const typeNames = {
    residential: "Жилые (лучшая репутация)",
    datacenter: "Датацентровые (режут чаще)",
    mobile: "Мобильные", unknown: "Тип не определён",
  };
  const byType = Object.entries(summary.by_type || {})
    .sort((a, b) => b[1] - a[1])
    .map(([kind, count]) => [typeNames[kind] || kind, `${count} адресов`]);

  const countries = Object.entries(summary.countries || {})
    .sort((a, b) => b[1] - a[1]).slice(0, 12)
    .map(([code, count]) => [code, `${count} адресов`]);

  host.innerHTML = `
    <div class="pmetrics">
      ${metric("Реальная ротация", `${unique} / ${total}`,
               "разных выходных IP — столько адресов видит почтовик")}
      ${metric("Дубли по выходу", dupes,
               dupes ? `самая крупная группа — ${summary.largest_group || 0}` : "каждый прокси даёт свой адрес")}
      ${metric("Скорость (медиана)", median != null ? `${median} мс` : "—",
               summary.latency_min != null ? `от ${summary.latency_min} до ${summary.latency_max} мс` : "")}
    </div>
    ${block("Пригодность по провайдерам",
            "Спрошено у самих почтовиков пробой до MAIL FROM, а не выведено из списков.",
            fitness)}
    ${block("Тип выходных адресов",
            "Фильтры смотрят именно на это: датацентровый IP блокируется чаще жилого.",
            byType)}
    ${block("География", "Прокси из страны получателя выбирается первым.", countries)}
    ${block("Гигиена адресов",
            "PTR нужен Yahoo и AOL; чёрные списки закрывают Outlook, iCloud и GMX.",
            [["С обратным DNS (PTR)", `${summary.with_ptr || 0}`],
             ["PTR проверить не удалось", `${summary.ptr_unknown || 0}`],
             ["В чёрных списках", `${summary.in_dnsbl || 0}`],
             ["Имя в PTR выдаёт прокси/VPN", `${summary.rdns_dirty || 0}`]])}
  `;
}

/* ============================================================
   Опрос состояния
   ============================================================ */

const STATE_TEXT = {
  idle: "Готов к работе", running: "Идёт проверка",
  paused: "Пауза", done: "Проверка завершена",
};

const PARSER_STATE_TEXT = {
  idle: "Готов к работе", running: "Идёт сбор",
  paused: "Пауза", done: "Сбор завершён",
};

/* Значок в шапке один, а прогонов может идти два. Показываем состояние
   того экрана, на который человек сейчас смотрит: иначе «Идёт проверка»
   висело бы над сбором адресов и наоборот. */
function syncRunState() {
  const parserMode = ui.mode === "parser";
  const state = parserMode ? (parser.state || "idle") : (ui.state || "idle");
  const badge = $("#runState");
  badge.dataset.state = state;
  setText($("#runStateText"),
          (parserMode ? PARSER_STATE_TEXT : STATE_TEXT)[state] || state);
}

let lastProxySig = "";

async function tick() {
  let s;
  try {
    s = await api("state");
  } catch {
    return;                       // мост ещё не поднялся или окно закрывается
  }

  ui.running = s.running;

  ui.state = s.state;
  syncRunState();

  setText($("#statValid"),   num(s.counts.valid));
  setText($("#statInvalid"), num(s.counts.invalid));
  setText($("#statUnknown"), num(s.counts.unknown));
  setText($("#statTotal"),   num(s.counts.total));
  setText($("#statSpam"),    num(s.counts.spam));
  setText($("#statNames"),   num(s.counts.names));

  const { current, total, pct } = s.progress;
  setText($("#progressLabel"), total
    ? `Проверено ${num(current)} из ${num(total)}`
    : "Проверка ещё не запускалась");
  setText($("#progressPct"), `${pct}%`);
  $("#progressBar").style.width = `${pct}%`;
  $("#progressWrap").classList.toggle("is-done", pct === 100 && total > 0);

  appendLog(s.log);
  setText($("#logNote"), s.dropped ? `строк лога пропущено: ${num(s.dropped)}` : "");

  $("#runControls").hidden = !(s.state === "running" || s.state === "paused");
  $("#btnStart").disabled = s.running || $("#startHint").classList.contains("is-ready") === false;
  setText($("#btnPause"), s.state === "paused" ? "Продолжить" : "Пауза");

  if (s.proxy) {
    const sig = JSON.stringify(s.proxy).slice(0, 200);
    if (sig !== lastProxySig) { lastProxySig = sig; renderProxy(s.proxy); }
  }

  if (ui.tab === "results" && s.log.length) await refreshRows(true);
}

/* ============================================================
   События
   ============================================================ */

function bindDrop(dropId, kind) {
  const el = $(dropId);
  el.addEventListener("click", async () => renderSources(await api("choose", { kind })));
  el.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); el.click(); }
  });
  el.addEventListener("dragover", (e) => { e.preventDefault(); el.classList.add("is-over"); });
  el.addEventListener("dragleave", () => el.classList.remove("is-over"));
  el.addEventListener("drop", (e) => {
    e.preventDefault();
    el.classList.remove("is-over");
    // WebView2 не отдаёт странице путь к файлу — только содержимое.
    // Читаем его и передаём текстом: для пользователя результат тот же.
    const file = e.dataTransfer.files && e.dataTransfer.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async () => {
      renderSources(await api("paste", { kind, text: String(reader.result || "") }));
      toast(`Загружено: ${file.name}`, "ok");
    };
    reader.readAsText(file);
  });
}

bindDrop("#dropEmails", "emails");
bindDrop("#dropProxies", "proxies");

$("#clearEmails").addEventListener("click", async (e) => {
  e.stopPropagation();
  renderSources(await api("clear", { kind: "emails" }));
});
$("#clearProxies").addEventListener("click", async (e) => {
  e.stopPropagation();
  renderSources(await api("clear", { kind: "proxies" }));
});

/* Вставка текстом */
let pasteKind = "emails";
const pasteModal = $("#pasteModal");
$("#pasteEmails").addEventListener("click", () => {
  pasteKind = "emails";
  setText($("#pasteTitle"), "Вставьте список адресов");
  $("#pasteArea").value = "";
  pasteModal.showModal();
});
$("#pasteProxies").addEventListener("click", () => {
  pasteKind = "proxies";
  setText($("#pasteTitle"), "Вставьте список прокси");
  $("#pasteArea").value = "";
  pasteModal.showModal();
});
pasteModal.addEventListener("close", async () => {
  if (pasteModal.returnValue !== "ok") return;
  const text = $("#pasteArea").value;
  if (!text.trim()) return;
  renderSources(await api("paste", { kind: pasteKind, text }));
  toast("Список добавлен", "ok");
});

/* Настройки */
const threads = $("#threads"), timeout = $("#timeout");
threads.addEventListener("input", () => setText($("#threadsOut"), threads.value));
timeout.addEventListener("input", () => setText($("#timeoutOut"), timeout.value));

$$(".seg__item").forEach((btn) => btn.addEventListener("click", () => {
  $$(".seg__item").forEach((b) => b.classList.remove("is-active"));
  btn.classList.add("is-active");
  ui.country = btn.dataset.country;
  setText($("#countryHint"), ui.country === "accuracy"
    ? "заполнено реже, но вернее: слабое распределение отбрасывается"
    : "заполнено почти всегда, ~треть стран — догадка");
}));

/* Прогон */
$("#btnStart").addEventListener("click", async () => {
  const res = await api("start", {
    threads: Number(threads.value), timeout: Number(timeout.value),
    ai: $("#optAi").checked, osint: $("#optOsint").checked,
    cache: $("#optCache").checked, country: ui.country,
  });
  if (!res.ok) { toast(res.error || "Не удалось запустить", "bad"); return; }
  logBox.replaceChildren();
  toast("Проверка запущена", "ok");
});
$("#btnPause").addEventListener("click", () => api("pause"));
$("#btnStop").addEventListener("click", () => api("stop"));

/* Вкладки. Селекторы привязаны к своему экрану: с появлением второго
   голое ".tab" начало бы гасить и чужие вкладки заодно. */
$$("#viewValidator .tab").forEach((tab) => tab.addEventListener("click", () => {
  $$("#viewValidator .tab").forEach((t) => t.classList.remove("is-active"));
  tab.classList.add("is-active");
  ui.tab = tab.dataset.tab;
  $$("#viewValidator .tabpane").forEach((p) =>
    p.classList.toggle("is-active", p.dataset.pane === ui.tab));
  if (ui.tab === "results") refreshRows(true);
}));

/* Режимы: оба экрана живут в этом же окне. */
function showMode(mode) {
  ui.mode = mode;
  $$(".mode").forEach((b) => {
    const on = b.dataset.mode === mode;
    b.classList.toggle("is-active", on);
    b.setAttribute("aria-selected", String(on));
  });
  $("#viewValidator").hidden = mode !== "validator";
  $("#viewParser").hidden = mode !== "parser";
  syncRunState();
}
$$(".mode").forEach((btn) =>
  btn.addEventListener("click", () => showMode(btn.dataset.mode)));

/* Фильтры выборки */
$$("#filters input").forEach((box) => box.addEventListener("change", () => {
  ui.groups = $$("#filters input:checked").map((b) => b.value);
  if (!ui.groups.length) { box.checked = true; ui.groups = [box.value]; }
  ui.page = 1;
  refreshRows(true);
}));

$("#minScore").addEventListener("change", () => {
  ui.minScore = Math.max(0, Math.min(100, Number($("#minScore").value) || 0));
  $("#minScore").value = ui.minScore;
  ui.page = 1;
  refreshRows(true);
});

$("#pagePrev").addEventListener("click", () => { ui.page = Math.max(1, ui.page - 1); refreshRows(true); });
$("#pageNext").addEventListener("click", () => { ui.page += 1; refreshRows(true); });

/* Действия над выборкой */
$("#btnCopy").addEventListener("click", async () => {
  const res = await api("copy_rows", { groups: ui.groups, minScore: ui.minScore });
  if (!res.count) { toast("В выборке пусто", "bad"); return; }
  await navigator.clipboard.writeText(res.text);
  toast(`Скопировано адресов: ${num(res.count)}` + (res.capped ? " (потолок буфера)" : ""), "ok");
});

$("#btnSuppress").addEventListener("click", async () => {
  const res = await api("choose_suppression");
  toast(res.path ? `Отписки: ${res.path}` : "Список отписок снят");
});

$("#btnExport").addEventListener("click", async () => {
  const res = await api("export", {
    groups: ui.groups, minScore: ui.minScore, chunk: Number($("#chunk").value) || 0,
  });
  if (res.cancelled) return;
  toast(res.ok ? "Сохраняю в фоне — окно не ждёт" : (res.error || "Не удалось"),
        res.ok ? "ok" : "bad");
});

$("#copyLog").addEventListener("click", async () => {
  await navigator.clipboard.writeText(logBox.textContent);
  toast("Лог скопирован", "ok");
});


/* ============================================================
   Сбор адресов
   ============================================================ */

const pLogBox = $("#pLog");

function appendParserLog(lines) {
  if (!lines || !lines.length) return;
  const atBottom = pLogBox.scrollTop + pLogBox.clientHeight >= pLogBox.scrollHeight - 24;
  const frag = document.createDocumentFragment();
  for (const line of lines) {
    const span = document.createElement("span");
    span.className = `l-${line.tag || "info"}`;
    span.textContent = line.text + "\n";
    frag.appendChild(span);
  }
  pLogBox.appendChild(frag);
  while (pLogBox.childNodes.length > MAX_LOG_NODES) pLogBox.removeChild(pLogBox.firstChild);
  if (atBottom) pLogBox.scrollTop = pLogBox.scrollHeight;
}

function renderFound(data) {
  const body = $("#pGridBody");
  const frag = document.createDocumentFragment();
  for (const row of data.rows) {
    const tr = document.createElement("tr");
    const email = document.createElement("td");
    email.className = "c-email";
    email.textContent = row.email;
    email.title = row.email;
    const dork = document.createElement("td");
    dork.className = "c-dork";
    dork.textContent = row.dork;
    dork.title = row.dork;
    tr.append(email, dork);
    frag.appendChild(tr);
  }
  body.replaceChildren(frag);
  $("#pGridEmpty").hidden = data.total > 0;
  setText($("#pPageInfo"), `Стр. ${data.page} / ${data.pages}`);
  setText($("#pFoundNote"), data.total ? `${num(data.total)} адресов` : "");
  parser.page = data.page;
  parser.pages = data.pages;
}

async function refreshFound(force = false) {
  const data = await api("parser_page", { page: parser.page });
  if (force || data.total !== parser.total) {
    parser.total = data.total;
    renderFound(data);
  }
}

let enginesFilled = false;

async function parserTick() {
  let s;
  try {
    s = await api("parser_state");
  } catch {
    return;
  }

  if (!enginesFilled && s.engines.length) {
    enginesFilled = true;
    const select = $("#pEngine");
    select.replaceChildren();
    for (const name of s.engines) {
      const option = document.createElement("option");
      option.value = name;
      option.textContent = name;
      select.appendChild(option);
    }
  }

  parser.state = s.state;
  parser.running = s.running;
  syncRunState();

  setText($("#pStatDorks"), `${num(s.stats.dorksDone)} / ${num(s.stats.dorksTotal)}`);
  setText($("#pStatPages"), num(s.stats.pages));
  setText($("#pStatSnippets"), num(s.stats.snippets));
  setText($("#pStatFound"), num(s.stats.found));

  const { current, total, pct, label } = s.progress;
  setText($("#pProgressLabel"), total
    ? `${label}: ${num(current)} из ${num(total)}`
    : "Сбор ещё не запускался");
  setText($("#pProgressPct"), `${pct}%`);
  $("#pProgressBar").style.width = `${pct}%`;

  appendParserLog(s.log);

  $("#pRunControls").hidden = !(s.state === "running" || s.state === "paused");
  setText($("#pBtnPause"), s.state === "paused" ? "Продолжить" : "Пауза");
  $("#pBtnStart").disabled = s.running ||
    $("#pStartHint").classList.contains("is-ready") === false;

  if (parser.tab === "found") await refreshFound();
}

/* ── обработчики второго экрана ── */

bindDrop("#dropDorks", "dorks");
bindDrop("#dropPproxy", "pproxy");

$("#clearDorks").addEventListener("click", async (e) => {
  e.stopPropagation();
  renderSources(await api("clear", { kind: "dorks" }));
});
$("#clearPproxy").addEventListener("click", async (e) => {
  e.stopPropagation();
  renderSources(await api("clear", { kind: "pproxy" }));
});

$("#pasteDorks").addEventListener("click", () => {
  pasteKind = "dorks";
  setText($("#pasteTitle"), "Вставьте поисковые запросы");
  $("#pasteArea").value = "";
  pasteModal.showModal();
});
$("#pastePproxy").addEventListener("click", () => {
  pasteKind = "pproxy";
  setText($("#pasteTitle"), "Вставьте список прокси");
  $("#pasteArea").value = "";
  pasteModal.showModal();
});

const pThreads = $("#pThreads"), pTimeout = $("#pTimeout");
pThreads.addEventListener("input", () => setText($("#pThreadsOut"), pThreads.value));
pTimeout.addEventListener("input", () => setText($("#pTimeoutOut"), pTimeout.value));

/* Подсказка под выбором поисковика: у Tor-движков и прокси-движков
   требования разные, и узнавать об этом из пустого лога — плохо. */
$("#pEngine").addEventListener("change", () => {
  const name = $("#pEngine").value;
  setText($("#pEngineHint"),
    name.includes("Tor") ? "поднимет собственный Tor — прокси не нужны"
    : name.includes("Proxies") ? "пойдёт через ваши прокси — загрузите их шагом 2"
    : "ходит напрямую, прокси не нужны");
});

$("#pBtnStart").addEventListener("click", async () => {
  const res = await api("parser_start", {
    engine: $("#pEngine").value,
    threads: Number(pThreads.value),
    timeout: Number(pTimeout.value),
  });
  if (!res.ok) { toast(res.error || "Не удалось запустить", "bad"); return; }
  pLogBox.replaceChildren();
  parser.total = -1;
  toast("Сбор запущен", "ok");
});
$("#pBtnPause").addEventListener("click", () => api("parser_pause"));
$("#pBtnStop").addEventListener("click", () => api("parser_stop"));

$$("#viewParser .tab").forEach((tab) => tab.addEventListener("click", () => {
  $$("#viewParser .tab").forEach((t) => t.classList.remove("is-active"));
  tab.classList.add("is-active");
  parser.tab = tab.dataset.ptab;
  $$("#viewParser .tabpane").forEach((p) =>
    p.classList.toggle("is-active", p.dataset.ppane === parser.tab));
  if (parser.tab === "found") refreshFound(true);
}));

$("#pPrev").addEventListener("click", () => {
  parser.page = Math.max(1, parser.page - 1);
  refreshFound(true);
});
$("#pNext").addEventListener("click", () => {
  parser.page += 1;
  refreshFound(true);
});

$("#pCopyLog").addEventListener("click", async () => {
  await navigator.clipboard.writeText(pLogBox.textContent);
  toast("Лог скопирован", "ok");
});

$("#pCopyRows").addEventListener("click", async () => {
  const res = await api("parser_copy");
  if (!res.count) { toast("Пока нечего копировать"); return; }
  await navigator.clipboard.writeText(res.text);
  toast(`Скопировано адресов: ${num(res.count)}` + (res.capped ? " (потолок буфера)" : ""), "ok");
});

$("#pExport").addEventListener("click", async () => {
  const res = await api("parser_export");
  if (!res.ok) { if (res.error) toast(res.error, "bad"); return; }
  toast(`Сохраняю ${num(res.count)} адресов в ${res.path}`, "ok");
});

/* ============================================================ Старт */
refreshSources();
/* Хвост лога — чтобы после перезагрузки страницы терминал не оказался пустым
   при идущем прогоне: очередь к тому моменту уже отдана прошлой странице. */
/* Первый опрос — только после хвоста: иначе он успеет забрать очередь, и те
   же строки придут дважды. */
api("log_tail").then((r) => appendLog(r.log)).catch(() => {}).finally(tick);
setInterval(tick, 250);

api("parser_log_tail").then((r) => appendParserLog(r.log)).catch(() => {}).finally(parserTick);
/* Сбор опрашивается вдвое реже проверки: там события идут не потоком,
   а по странице выдачи, и чаще смотреть попросту нечего. */
setInterval(parserTick, 500);
