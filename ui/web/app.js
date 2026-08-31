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

/* Показать/спрятать, НЕ трогая раскладку.

   Атрибут hidden выкидывает элемент из потока, и всё, что ниже, прыгает
   вверх: появилась кнопка «Очистить» — уехали настройки; начался прогон —
   уехало всё под кнопкой запуска. Класс is-gone оставляет место занятым. */
function show(el, on) {
  if (el) el.classList.toggle("is-gone", !on);
}

/* Закрасить пройденную часть дорожки ползунка.

   Chromium (а WebView2 — это он) не даёт стилизовать заполненную часть
   отдельным псевдоэлементом, как Firefox, поэтому доля считается тут и
   уезжает в градиент переменной --fill. */
function paintRange(el) {
  if (!el) return;
  const min = Number(el.min || 0);
  const max = Number(el.max || 100);
  const value = Number(el.value || 0);
  const share = max > min ? ((value - min) / (max - min)) * 100 : 0;
  el.style.setProperty("--fill", `${share}%`);
}

/* Запереть весь ввод на время прогона.

   Список берётся по атрибуту data-lock из самой разметки, а не перечисляется
   здесь: иначе новый переключатель добавляют, а запереть его забывают, и
   владелец меняет настройки посреди проверки. Вкладки, фильтры, поиск,
   страницы и выгрузка этой пометки не носят — по уже полученным результатам
   ходить можно и нужно. */
function setLocked(on) {
  for (const el of $$("[data-lock]")) {
    if ("disabled" in el) el.disabled = on;
    el.classList.toggle("is-locked", on);
    // У div-зоны перетаскивания нет disabled — ей убираем и фокус, иначе
    // до неё можно дойти табом и нажать Enter.
    if (!("disabled" in el)) el.tabIndex = on ? -1 : 0;
  }
  document.body.classList.toggle("is-running", on);
  $$(".side").forEach((side) => side.classList.toggle("is-locked", on));
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
  // Грани отбора и поиск. Выбранное хранится множествами: порядок значений в
  // списке меняется по мере прогона (сортировка по количеству), а выбор от
  // этого зависеть не должен.
  facets: { country: new Set(), gender: new Set(), provider: new Set() },
  search: "",
  facetSig: "",
};

const FACET_TITLE = { country: "Страна", gender: "Пол", provider: "Почтовик" };

/* Запрос выборки — в одном месте: он уходит и за страницей, и за списками
   значений, и за копированием, и за выгрузкой. Разъехавшиеся копии этого
   объекта означали бы, что сохранённый файл не совпадает с тем, что на
   экране. */
function selection(extra = {}) {
  return Object.assign({
    groups: ui.groups,
    minScore: ui.minScore,
    country: [...ui.facets.country],
    gender: [...ui.facets.gender],
    provider: [...ui.facets.provider],
    search: ui.search,
  }, extra);
}

/* Сбор адресов держит своё состояние отдельно: два прогона могут идти
   одновременно, и мешать их счётчики в одну кучу нельзя. */
const parser = { tab: "log", page: 1, running: false, total: -1 };

/* ── источники: файлы и вставленный текст ─────────────────── */

/* Что сейчас лежит в каждом поле, текстом. null означает «источник есть, но
   он слишком велик, чтобы показывать его в поле». */
const sourceText = { emails: null, proxies: null, dorks: null, pproxy: null };

const EMPTY_HINT = {
  emails:  "txt или csv · можно перетащить сюда",
  proxies: "socks5, socks4 или http",
  dorks:   "по запросу в строке · можно перетащить сюда",
  pproxy:  "нужны движкам с пометкой Proxies",
};

// Сколько строк загружено. null означает «ещё считаю»: на большом файле
// счёт занимает секунды, и показать 0 нельзя — владелец прочитает это как
// «файл пустой».
function linesLabel(info) {
  if (!info.count) return "";
  if (info.lines === null || info.lines === undefined) return "считаю строки…";
  return `${num(info.lines)} ${plural(info.lines, "строка", "строки", "строк")}`;
}

function plural(n, one, few, many) {
  const a = Math.abs(n) % 100, b = a % 10;
  if (a > 10 && a < 20) return many;
  if (b > 1 && b < 5) return few;
  if (b === 1) return one;
  return many;
}

function renderSources(data) {
  const bind = (prefix, info, dropId, clearId) => {
    // В заголовке — сколько СТРОК, а не сколько файлов. «13 источника» не
    // отвечает на вопрос «сколько прокси я загрузил», а именно он и важен.
    const lines = linesLabel(info);
    setText($(`#${prefix}Title`), lines ? `${info.title} · ${lines}` : info.title);
    const hint = $(`#${prefix}Hint`);
    if (info.count) {
      setText(hint, info.detail);
      $(dropId).classList.add("is-set");
      show($(clearId), true);
    } else {
      setText(hint, EMPTY_HINT[prefix] || "");
      $(dropId).classList.remove("is-set");
      show($(clearId), false);
    }
  };
  // Текст источников запоминается, чтобы поле вставки открывалось с тем, что
  // уже загружено, — независимо от того, файлом это пришло или руками.
  sourceText.emails = data.emails.editable ? data.emails.text : null;
  sourceText.proxies = data.proxies.editable ? data.proxies.text : null;
  sourceText.dorks = data.dorks.editable ? data.dorks.text : null;
  sourceText.pproxy = data.pproxy.editable ? data.pproxy.text : null;

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
/* Возраст вердикта в подсказке и пометка устаревшего.

   «Годен» месячной давности — уже не то же самое, что «Годен» сегодняшний:
   ящик могли удалить на следующий день после проверки. Отдельной колонки не
   заводим — она вытеснила бы что-то нужное; хватает цвета и подсказки. */
function whenTitle(row) {
  const base = row.when || "";
  if (!row.age || typeof row.age.days !== "number") return base;
  const days = row.age.days;
  const word = days === 0 ? "сегодня"
    : days === 1 ? "вчера"
    : `${days} дн. назад`;
  return row.age.stale
    ? `${base} — проверено ${word}, вердикт устарел: стоит перепроверить`
    : `${base} — проверено ${word}`;
}

function shortGender(value) {
  const v = String(value || "").toLowerCase();
  if (v.startsWith("муж")) return "М";
  if (v.startsWith("жен")) return "Ж";
  return value || "";
}

/* Кружок с инициалами и устойчивым цветом.

   Цвет выводится из самого адреса, поэтому у одного человека он всегда один
   и тот же — строку узнаёшь боковым зрением, не читая. Насыщенность и
   светлота зафиксированы: случайный цвет из всего пространства даёт то
   невидимые на тёмном фоне, то кислотные кружки. */
function avatarCell(row) {
  const box = document.createElement("span");
  box.className = "who";

  const ava = document.createElement("span");
  ava.className = "ava";

  const email = String(row.email || "");
  let hue = 0;
  for (let i = 0; i < email.length; i += 1) {
    hue = (hue * 31 + email.charCodeAt(i)) % 360;
  }
  ava.style.background = `hsl(${hue} 58% 42%)`;
  ava.textContent = initials(email);

  if (row.avatar) {
    const img = document.createElement("img");
    img.src = `https://www.gravatar.com/avatar/${row.avatar}?s=44&d=404`;
    img.alt = "";
    img.loading = "lazy";
    // Не загрузилась — остаётся кружок с инициалами. Без этого на машине без
    // сети в каждой строке висела бы битая картинка.
    img.addEventListener("error", () => img.remove());
    ava.appendChild(img);
  }

  const mail = document.createElement("span");
  mail.className = "who__mail";
  mail.textContent = email;

  box.append(ava, mail);
  return box;
}

/* Две буквы из адреса: по ним кружок отличается от соседнего. */
function initials(email) {
  const local = String(email || "").split("@")[0] || "";
  const parts = local.split(/[._-]+/).filter(Boolean);
  if (parts.length >= 2) {
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }
  return local.slice(0, 2).toUpperCase();
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
      ["c-email", null, row.email],
      ["c-verdict", null, null],
      ["c-score", null, null],
      ["c-prov", row.provider, row.provider],
      ["c-reason", row.reason, row.reason],
      ["c-name", row.name, row.name],
      ["c-gender", shortGender(row.gender), row.gender],
      ["c-country", row.country, row.country],
      ["c-when", shortDate(row.when), whenTitle(row)],
    ];
    cells.forEach(([cls, text, title], index) => {
      const td = document.createElement("td");
      td.className = cls;
      if (index === 0) {
        td.appendChild(avatarCell(row));
        td.title = row.email;
      } else if (index === 1) {
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
        if (cls === "c-when" && row.age && row.age.stale) td.classList.add("is-stale");
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
  const sig = JSON.stringify(selection({ page: ui.page }));
  if (!force && sig === ui.lastSig && !ui.running) return;
  ui.lastSig = sig;
  renderRows(await api("page", selection({ page: ui.page })));
  await refreshFacets();
}

/* ── грани отбора ─────────────────────────────────────────── */

/* Списки значений приходят из базы вместе с количествами. Показывать
   справочник стран целиком было бы враньём: пункт, за которым нет ни одной
   строки, обещает выборку, которой не существует. */
async function refreshFacets() {
  let data;
  try {
    data = await api("facets", selection());
  } catch {
    return;
  }

  for (const facet of Object.keys(FACET_TITLE)) {
    const box = $(`#facet${facet[0].toUpperCase()}${facet.slice(1)}`);
    if (!box) continue;
    const list = box.querySelector(".facet__list");
    const values = data.facets[facet] || [];
    const chosen = ui.facets[facet];

    const frag = document.createDocumentFragment();
    for (const item of values) {
      const label = document.createElement("label");
      label.className = "facet__item";

      const input = document.createElement("input");
      input.type = "checkbox";
      input.value = item.value;
      input.checked = chosen.has(item.value);
      input.addEventListener("change", () => {
        if (input.checked) chosen.add(item.value); else chosen.delete(item.value);
        ui.page = 1;
        refreshRows(true);
      });

      const text = document.createElement("span");
      // Пустое значение — это «не определено», а не безымянный пункт: без
      // подписи в списке была бы пустая строка с галочкой.
      text.textContent = item.value === "" ? "не определено" : item.value;
      text.title = text.textContent;

      const count = document.createElement("b");
      count.textContent = num(item.count);

      label.append(input, text, count);
      frag.appendChild(label);
    }
    if (!values.length) {
      const empty = document.createElement("div");
      empty.className = "facet__empty";
      empty.textContent = "в выборке пусто";
      frag.appendChild(empty);
    }
    list.replaceChildren(frag);

    box.classList.toggle("is-on", chosen.size > 0);
    setText(box.querySelector(".facet__count"), chosen.size ? `· ${chosen.size}` : "");
  }

  const any = ui.search || ui.minScore ||
    Object.values(ui.facets).some((set) => set.size > 0);
  show($("#resetFilters"), !!any);
}

function resetFacets() {
  for (const set of Object.values(ui.facets)) set.clear();
  ui.search = "";
  ui.minScore = 0;
  $("#search").value = "";
  $("#minScore").value = 0;
  show($("#searchClear"), false);
  ui.page = 1;
  refreshRows(true);
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

/* Отступление при недоступном мосте.

   Опрос идёт четыре раза в секунду, и когда мост падает или окно закрывают,
   страница продолжает стучаться с той же частотой. Замечено вживую: браузер
   перестаёт выдавать сокеты и сыплет ERR_INSUFFICIENT_RESOURCES, а вместе с
   неудачными запросами тонут и удачные, когда мост возвращается. Пропускаем
   тики, удваивая паузу до восьми, — восстановление занимает максимум две
   секунды, а холостых запросов на порядок меньше. */
let missed = 0;
let skip = 0;

let logSeen = 0;                 // номер последней показанной строки лога

async function tick() {
  if (skip > 0) { skip -= 1; return; }
  let s;
  try {
    s = await api("state", { logSince: logSeen });
  } catch {
    missed += 1;
    skip = Math.min(8, missed);   // мост ещё не поднялся или окно закрывается
    return;
  }
  missed = 0;

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
  const px = s.proxyProgress || { checked: 0, seen: 0, running: false };
  if (px.running) {
    // Проверка прокси идёт ДО проверки почт. Процента здесь нет и быть не
    // может: список ещё читается, и целого, от которого считать долю, не
    // существует. Раньше сюда попадали те же числа под подписью «Проверено
    // X из Y», и владелец читал их как адреса — при нулях во всех карточках.
    setText($("#progressLabel"),
      `Проверяю прокси: ${num(px.checked)} · прочитано ${num(px.seen)}, файл ещё читается`);
    setText($("#progressPct"), "");
    $("#progressBar").style.width = "0%";
    $("#progressWrap").classList.remove("is-done");
  } else {
    setText($("#progressLabel"), total
      ? `Проверено адресов: ${num(current)} из ${num(total)}`
      : "Проверка ещё не запускалась");
    setText($("#progressPct"), `${pct}%`);
    $("#progressBar").style.width = `${pct}%`;
    $("#progressWrap").classList.toggle("is-done", pct === 100 && total > 0);
  }

  appendLog(s.log);
  if (typeof s.logSeq === "number") logSeen = Math.max(logSeen, s.logSeq);
  setText($("#logNote"), s.dropped ? `строк лога пропущено: ${num(s.dropped)}` : "");

  const active = s.state === "running" || s.state === "paused";
  show($("#runControls"), active);
  show($("#btnStart"), !active);
  $("#btnStart").disabled = s.running || $("#startHint").classList.contains("is-ready") === false;
  setText($("#btnPause"), s.state === "paused" ? "Продолжить" : "Пауза");

  // Запор общий на оба экрана: пока идёт хоть один прогон, менять исходные
  // данные нельзя нигде. Иначе можно уйти на сбор адресов и подменить базу
  // проверке, которая её как раз читает.
  syncLock();

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
  el.addEventListener("click", async () => {
    const data = await api("choose", { kind });
    renderSources(data);
    if (data.error) toast(data.error, "bad");
  });
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
      const data = await api("paste", { kind, text: String(reader.result || "") });
      renderSources(data);
      // Перетаскивание проходит ту же проверку, что и вставка: файл, брошенный
      // не в ту зону, — самый частый способ перепутать списки.
      toast(data.error || `Загружено: ${file.name}`, data.error ? "bad" : "ok");
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

/* Вставка текстом.

   Плейсхолдер показывает ВСЕ форматы, которые движок действительно
   разбирает, — примерами, а не описанием. «Одна запись в строке» не
   отвечает ни на один вопрос, который возникает перед вставкой: с
   разделителем или без, можно ли имя, что делать с логином и паролем
   прокси. */
const PASTE_FORMATS = {
  emails: {
    title: "Вставьте список адресов",
    hint: "Одна запись в строке. Кроме адреса можно дать имя, пол и страну — " +
          "разделитель любой из , ; : | или табуляция. Первая строка может " +
          "быть заголовком CSV.",
    placeholder: [
      "ivan@gmail.com",
      "anna@yahoo.com;Анна;Женский;США",
      "petr@mail.ru,Пётр Смирнов,Мужской,Россия",
      "olga@outlook.com|Ольга|Женский",
      "email;name;gender;country",
      "иван@почта.рф",
    ].join("\n"),
  },
  proxies: {
    title: "Вставьте список прокси",
    hint: "Одна запись в строке. Схема необязательна; логин и пароль можно " +
          "дать двумя способами. Нужен открытый порт 25 — 587 и 465 для " +
          "проверки не годятся.",
    placeholder: [
      "1.2.3.4:8080",
      "1.2.3.4:8080:логин:пароль",
      "логин:пароль@1.2.3.4:8080",
      "socks5://1.2.3.4:1080",
      "http://логин:пароль@proxy.example.com:3128",
    ].join("\n"),
  },
  dorks: {
    title: "Вставьте поисковые запросы",
    hint: "По запросу в строке. Работают операторы поисковиков; кавычки " +
          "ищут точное совпадение.",
    placeholder: [
      'site:linkedin.com "@gmail.com" маркетинг',
      'intext:"@yahoo.com" контакты',
      'inurl:contact "@aol.com"',
      'filetype:pdf "@gmail.com" резюме',
      '"@mail.ru" отдел продаж',
    ].join("\n"),
  },
};
PASTE_FORMATS.pproxy = PASTE_FORMATS.proxies;

let pasteKind = "emails";
const pasteModal = $("#pasteModal");

function openPaste(kind) {
  pasteKind = kind;
  const spec = PASTE_FORMATS[kind] || PASTE_FORMATS.emails;
  setText($("#pasteTitle"), spec.title);
  setText($("#pasteHint"), spec.hint);
  const area = $("#pasteArea");
  // Открываем поле с тем, что уже загружено: владелец видит свои данные и
  // правит их на месте, а не гадает, что там сейчас. Файл при этом
  // равноправен со вставкой — он тоже лежит здесь текстом.
  area.value = sourceText[kind] || "";
  area.placeholder = spec.placeholder;
  setText($("#pasteError"), "");
  show($("#pasteError"), false);
  pasteModal.showModal();
}

$("#pasteEmails").addEventListener("click", () => openPaste("emails"));
$("#pasteProxies").addEventListener("click", () => openPaste("proxies"));

/* Отправка идёт через submit, а не через закрытие окна: при отказе окно
   должно ОСТАТЬСЯ открытым с набранным текстом. Закрыть его и показать
   всплывашку значит заставить владельца искать и вставлять список заново. */
pasteModal.querySelector("form").addEventListener("submit", async (event) => {
  if (pasteModal.returnValue === "cancel" ||
      (event.submitter && event.submitter.value === "cancel")) return;

  event.preventDefault();
  const text = $("#pasteArea").value;
  if (!text.trim()) {
    setText($("#pasteError"), "Пусто — нечего добавлять.");
    show($("#pasteError"), true);
    return;
  }

  // Правка заменяет содержимое поля целиком, а не добавляется к нему: иначе
  // исправленный список лёг бы поверх старого, и оба ушли бы в проверку.
  if (sourceText[pasteKind] !== null && sourceText[pasteKind] !== "") {
    await api("clear", { kind: pasteKind });
  }
  const data = await api("paste", { kind: pasteKind, text });
  renderSources(data);
  if (data.error) {
    // Проверку делает питон, а не страница: два разных разбора одних и тех
    // же данных разъезжаются, и тогда окно принимает то, что движок потом
    // не прочтёт.
    setText($("#pasteError"), data.error);
    show($("#pasteError"), true);
    return;
  }
  show($("#pasteError"), false);
  pasteModal.close();
  toast("Список добавлен", "ok");
});

/* Настройки */
const threads = $("#threads"), timeout = $("#timeout");
threads.addEventListener("input", () => {
  setText($("#threadsOut"), threads.value);
  paintRange(threads);
});
timeout.addEventListener("input", () => {
  setText($("#timeoutOut"), timeout.value);
  paintRange(timeout);
});

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

/* Поиск с задержкой: запрос на каждое нажатие клавиши — это десяток
   обращений к базе на одно слово, и на большой базе они начинают
   наступать друг другу на пятки. */
let searchTimer = null;
$("#search").addEventListener("input", () => {
  const value = $("#search").value.trim();
  show($("#searchClear"), value.length > 0);
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    ui.search = value;
    ui.page = 1;
    refreshRows(true);
  }, 220);
});

$("#search").addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    $("#search").value = "";
    $("#search").dispatchEvent(new Event("input"));
  }
});

$("#searchClear").addEventListener("click", () => {
  $("#search").value = "";
  $("#search").dispatchEvent(new Event("input"));
  $("#search").focus();
});

$("#resetFilters").addEventListener("click", resetFacets);

/* Список граней закрывается по щелчку мимо него — иначе три раскрытых
   списка перекрывают таблицу, ради которой всё и затевалось. */
document.addEventListener("click", (event) => {
  for (const box of $$(".facet[open]")) {
    if (!box.contains(event.target)) box.open = false;
  }
});

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
  const res = await api("copy_rows", selection());
  if (!res.count) { toast("В выборке пусто", "bad"); return; }
  await navigator.clipboard.writeText(res.text);
  toast(`Скопировано адресов: ${num(res.count)}` + (res.capped ? " (потолок буфера)" : ""), "ok");
});

$("#btnSuppress").addEventListener("click", async () => {
  const res = await api("choose_suppression");
  if (res.error) { toast(res.error, "bad"); return; }
  toast(res.path ? `Отписки: ${res.path}` : "Список отписок снят");
});

$("#btnExport").addEventListener("click", async () => {
  // Поле «файлы по» тоже приводится к числу: пустое и мусорное значит «одним
  // файлом», отрицательное — опечатка, а не пожелание.
  const chunk = Math.max(0, Math.floor(Number($("#chunk").value) || 0));
  $("#chunk").value = chunk;
  const res = await api("export", selection({ chunk }));
  if (res.cancelled) return;
  toast(res.ok ? "Сохраняю в фоне — окно не ждёт" : (res.error || "Не удалось"),
        res.ok ? "ok" : "bad");
});

$("#segmentBy").addEventListener("change", async () => {
  const by = $("#segmentBy").value;
  if (!by) return;
  $("#segmentBy").value = "";
  const res = await api("export_segments", selection({ by }));
  if (res.cancelled) return;
  toast(res.ok ? "Раскладываю в фоне — смотрите лог" : (res.error || "Не удалось"),
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
  show($("#pGridEmpty"), data.total === 0);
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

let parserMissed = 0;
let parserSkip = 0;

async function parserTick() {
  if (parserSkip > 0) { parserSkip -= 1; return; }
  let s;
  try {
    s = await api("parser_state");
  } catch {
    parserMissed += 1;
    parserSkip = Math.min(8, parserMissed);
    return;
  }
  parserMissed = 0;

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
  syncLock();

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

  const pActive = s.state === "running" || s.state === "paused";
  show($("#pRunControls"), pActive);
  show($("#pBtnStart"), !pActive);
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

$("#pasteDorks").addEventListener("click", () => openPaste("dorks"));
$("#pastePproxy").addEventListener("click", () => openPaste("pproxy"));

const pThreads = $("#pThreads"), pTimeout = $("#pTimeout");
pThreads.addEventListener("input", () => {
  setText($("#pThreadsOut"), pThreads.value);
  paintRange(pThreads);
});
pTimeout.addEventListener("input", () => {
  setText($("#pTimeoutOut"), pTimeout.value);
  paintRange(pTimeout);
});

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

/* Запор общий: прогон валидатора и прогон сбора одинаково запрещают менять
   исходные данные. Отдельная функция, потому что состояние приходит двумя
   разными опросами, и каждый должен уметь его пересчитать. */
function syncLock() {
  setLocked(!!(ui.running || parser.running));
}

/* ============================================================ Старт */
[threads, timeout, pThreads, pTimeout].forEach(paintRange);
refreshSources();
/* Хвост лога — чтобы после перезагрузки страницы терминал не оказался пустым
   при идущем прогоне: очередь к тому моменту уже отдана прошлой странице. */
/* Хвост лога и опрос больше не спорят за одни и те же строки: хвост говорит,
   на каком номере он кончился, а опрос просит только то, что после него.
   Раньше порядок решал всё — если опрос успевал первым, пришедший следом
   хвост показывал те же строки второй раз. Владелец видел это как «дубликаты
   не удалились», хотя база схлопывалась правильно. */
api("log_tail")
  .then((r) => { appendLog(r.log); logSeen = Math.max(logSeen, r.seq || 0); })
  .catch(() => {})
  .finally(() => { tick(); setInterval(tick, 250); });

api("parser_log_tail").then((r) => appendParserLog(r.log)).catch(() => {}).finally(parserTick);
/* Сбор опрашивается вдвое реже проверки: там события идут не потоком,
   а по странице выдачи, и чаще смотреть попросту нечего. */
setInterval(parserTick, 500);
