const TOKEN = document.body.dataset.token;
const $  = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

async function api(method, payload = {}) {
  const res = await fetch(`/api/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Token": TOKEN },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {


    let причина = "";
    try {
      const тело = await res.json();
      причина = String((тело && тело.error) || "");
    } catch {

    }
    throw new Error(причина ? `${method}: ${причина}` : `${method}: ${res.status}`);
  }
  return res.json();
}


let crashReports = 0;

function reportClientCrash(message, where, stack) {


  if (crashReports >= 20) return;
  crashReports += 1;


  let вкладка = "";
  try {
    вкладка = (ui && ui.mode) ? String(ui.mode) : "";
  } catch {

  }

  try {
    fetch("/api/client_error", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Token": TOKEN },
      body: JSON.stringify({
        message: String(message || "").slice(0, 500),
        where: String(where || "").slice(0, 300),
        stack: String(stack || "").slice(0, 4000),
        mode: вкладка,
      }),
    }).catch(() => {});
  } catch {

  }
}


function describe(value) {
  if (value === null) return "null";
  if (value === undefined) return "undefined";
  try {
    if (typeof value === "string") return value || "(пустая строка)";
    if (value instanceof Error) {
      return `${value.name}: ${value.message || "(без текста)"}`;
    }
    const text = String(value);

    if (text === "[object Object]") {
      return JSON.stringify(value).slice(0, 400);
    }
    return text || `(пусто, тип ${typeof value})`;
  } catch {
    return `(не удалось описать, тип ${typeof value})`;
  }
}

window.addEventListener("error", (event) => {


  const target = event.target;
  const isResource = target && target !== window && target.tagName;
  const what = isResource
    ? `не загрузился ресурс <${String(target.tagName).toLowerCase()}> `
      + `${target.src || target.href || "(без адреса)"}`
    : describe(event.message);

  reportClientCrash(
    `[ошибка JS] ${what}`,
    `${event.filename || "источник не назван"}:${event.lineno || 0}`,
    event.error && event.error.stack);
}, true);


window.addEventListener("unhandledrejection", (event) => {
  const reason = event.reason;
  reportClientCrash(
    `[отказ обещания] ${describe(reason)}`,
    "необработанный отказ обещания",
    reason && reason.stack);
});


function onVisibilityChange() {
  if (document.visibilityState === "hidden") {


    return;
  }


  tick();
  parserTick();
  if (ui.tab === "results") refreshRows(true);
  if (parser.tab === "found") refreshFound(true);
}

document.addEventListener("visibilitychange", onVisibilityChange);


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


function setText(el, value) {
  const next = String(value);
  if (el.textContent !== next) el.textContent = next;
}


function show(el, on) {
  if (el) el.classList.toggle("is-gone", !on);
}


function paintRange(el) {
  if (!el) return;
  const min = Number(el.min || 0);
  const max = Number(el.max || 100);
  const value = Number(el.value || 0);
  const share = max > min ? ((value - min) / (max - min)) * 100 : 0;
  el.style.setProperty("--fill", `${share}%`);
}


function setLocked(on) {
  for (const el of $$("[data-lock]")) {
    if ("disabled" in el) el.disabled = on;
    el.classList.toggle("is-locked", on);


    if (!("disabled" in el)) el.tabIndex = on ? -1 : 0;
  }
  document.body.classList.toggle("is-running", on);
  $$(".side").forEach((side) => side.classList.toggle("is-locked", on));
}


const ui = {

  engineBusy: false,
  tab: "log",
  page: 1,


  groups: ["valid", "pending"],
  minScore: 0,


  country: "accuracy",
  running: false,
  mode: "validator",
  lastSig: "",


  opened: new Set(),


  facets: { country: new Set(), gender: new Set(), provider: new Set() },
  search: "",

  hideTypo: false,
  facetSig: "",

  base: null,
};

const FACET_TITLE = { country: "Страна", gender: "Пол", provider: "Почтовик" };


function selection(extra = {}) {
  return Object.assign({
    groups: ui.groups,
    minScore: ui.minScore,
    country: [...ui.facets.country],
    gender: [...ui.facets.gender],
    provider: [...ui.facets.provider],
    search: ui.search,
    hideTypo: ui.hideTypo,
  }, extra);
}


const parser = { tab: "log", page: 1, running: false, total: -1 };


const sourceText = { emails: null, proxies: null, dorks: null, pproxy: null };


let sourceInfo = null;

const EMPTY_HINT = {
  emails:  "txt или csv · можно перетащить сюда",
  proxies: "socks5, socks4 или http",
  dorks:   "по запросу в строке · можно перетащить сюда",
  pproxy:  "нужны движкам с пометкой Proxies",
};


function linesLabel(info) {
  if (!info.count) return "";
  if (info.lines === null || info.lines === undefined) return "считаю строки…";
  return `${num(info.lines)} ${plural(info.lines, "строка", "строки", "строк")}`;
}

function filesLabel(info) {


  return `${info.count} ${plural(info.count, "источник", "источника", "источников")}`;
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


    setText($(`#${prefix}Title`), info.count ? linesLabel(info) : info.title);
    const hint = $(`#${prefix}Hint`);
    const drop = $(dropId);
    if (info.count) {
      const hintText = `${filesLabel(info)} · ${info.detail}`;
      setText(hint, hintText);
      if (hint) hint.title = info.detail ? hintText : "";
      if (drop) {
        drop.classList.add("is-set");
        drop.title = info.detail || "";
      }
      show($(clearId), true);
    } else {
      setText(hint, EMPTY_HINT[prefix] || "");
      if (hint) hint.title = "";
      if (drop) {
        drop.classList.remove("is-set");
        drop.title = "";
      }
      show($(clearId), false);
    }
  };


  sourceText.emails = data.emails.editable ? data.emails.text : null;
  sourceText.proxies = data.proxies.editable ? data.proxies.text : null;
  sourceText.dorks = data.dorks.editable ? data.dorks.text : null;
  sourceText.pproxy = data.pproxy.editable ? data.pproxy.text : null;
  sourceInfo = data;

  bind("emails", data.emails, "#dropEmails", "#clearEmails");
  bind("proxies", data.proxies, "#dropProxies", "#clearProxies");
  bind("dorks", data.dorks, "#dropDorks", "#clearDorks");
  bind("pproxy", data.pproxy, "#dropPproxy", "#clearPproxy");

  const hint = $("#startHint");
  setText(hint, data.hint);
  hint.classList.toggle("is-ready", !!data.ready);
  $("#btnStart").disabled = !data.ready || ui.running || !!ui.engineBusy;

  const pHint = $("#pStartHint");
  setText(pHint, data.parserHint);
  pHint.classList.toggle("is-ready", !!data.parserReady);
  $("#pBtnStart").disabled = !data.parserReady || parser.running || !!parser.engineBusy;
}

let countPoll = null;


function showSources(data) {
  renderSources(data);
  armCountPoll(data);
  return data;
}


function armCountPoll(data) {


  const counting = ["emails", "proxies", "dorks", "pproxy"]
    .some((k) => data[k] && data[k].count && (data[k].lines === null || data[k].lines === undefined));
  clearTimeout(countPoll);
  if (counting) countPoll = setTimeout(refreshSources, 400);
}

async function refreshSources() { showSources(await api("sources")); }


const logBox = $("#log");
const MAX_LOG_NODES = 1200;


function clockOf(epochSeconds) {
  const d = new Date(epochSeconds * 1000);
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map((v) => String(v).padStart(2, "0")).join(":");
}


function fmtDur(seconds) {
  let s = Math.max(0, Math.round(Number(seconds) || 0));
  if (s < 60) return `${s} с`;
  let m = Math.floor(s / 60); s %= 60;
  if (m < 60) return `${m} мин ${String(s).padStart(2, "0")} с`;
  const h = Math.floor(m / 60); m %= 60;
  return `${h} ч ${String(m).padStart(2, "0")} мин`;
}


function logSpan(line) {
  const span = document.createElement("span");
  span.className = `l-${line.tag || "info"}`;
  if (typeof line.t === "number") {
    const t = document.createElement("span");
    t.className = "t";
    t.textContent = clockOf(line.t) + " ";
    span.appendChild(t);
  }
  span.appendChild(document.createTextNode(line.text + "\n"));
  return span;
}


let logShownTop = 0;
function appendLog(lines) {
  if (!lines || !lines.length) return;
  const atBottom = logBox.scrollTop + logBox.clientHeight >= logBox.scrollHeight - 24;
  const frag = document.createDocumentFragment();
  for (const line of lines) {
    if (typeof line.n === "number") {
      if (line.n <= logShownTop) continue;
      logShownTop = line.n;
    }
    frag.appendChild(logSpan(line));
  }
  logBox.appendChild(frag);
  while (logBox.childNodes.length > MAX_LOG_NODES) logBox.removeChild(logBox.firstChild);
  if (atBottom) logBox.scrollTop = logBox.scrollHeight;
}


function renderTrail(el, trail) {
  if (!el) return;
  const steps = Array.isArray(trail) ? trail : [];


  const sig = steps.map((s) => `${s.label}:${Math.floor(s.seconds || 0)}:${s.active ? 1 : 0}:${s.cut ? 1 : 0}`).join("|");
  if (el.dataset.sig === sig) return;
  el.dataset.sig = sig;
  const frag = document.createDocumentFragment();
  steps.forEach((s, i) => {
    if (i) {
      const sep = document.createElement("span");
      sep.className = "live__sep";
      sep.textContent = "›";
      frag.appendChild(sep);
    }
    const item = document.createElement("span");

    item.className = s.active ? "live__step is-active" : (s.cut ? "live__step is-cut" : "live__step");
    item.textContent = `${s.active ? "▶" : (s.cut ? "✗" : "✓")} ${s.label} · ${fmtDur(s.seconds)}`;
    frag.appendChild(item);
  });
  el.replaceChildren(frag);
}

function renderLive(id, a) {
  const box = document.getElementById(id);
  if (!box || !a) return;
  if (box.dataset.level !== a.level) box.dataset.level = a.level || "idle";
  const title = document.getElementById(`${id}Title`);
  if (title) setText(title, a.title || "");
  const detail = document.getElementById(`${id}Detail`);
  if (detail) {
    setText(detail, a.detail || "");
    detail.title = a.detail || "";
  }
  if (a.trail !== undefined) renderTrail(document.getElementById(`${id}Trail`), a.trail);
}


function renderNoLink(id, sinceMs) {
  const secs = (Date.now() - sinceMs) / 1000;
  if (secs < 3) return;
  renderLive(id, {
    level: "nolink",
    title: "Нет связи с движком",
    detail: `Окно работает, но движок не отвечает уже ${fmtDur(secs)}. ` +
            "Если это длится больше минуты — перезапустите программу: " +
            "уже проверенные адреса повторно проверяться не будут.",
  });
}


function tickClocks() {
  const now = clockOf(Date.now() / 1000);
  for (const el of document.querySelectorAll(".live__clock")) el.textContent = now;
}


const VERDICT_TEXT = {
  valid: "Годен",
  invalid: "Мёртв",
  spam: "Не слать",
  unknown: "Неясно",
  pending: "Не проверен",
};
const VERDICT_FULL = {
  valid: "Можно слать — доказано, что ящик существует",
  invalid: "Слать нельзя — доказано, что ящика нет",
  spam: "Не слать: ловушка, одноразовый, роль-адрес, переполненный или отключённый ящик",
  unknown: "Не доказано — ответа не получили",
  pending: "Ещё не проверен: строка из загруженной базы, вердикта пока нет — слать нельзя",
};


function shortDate(value) {
  const m = String(value || "").match(/^\d{4}-(\d{2})-(\d{2})\s+(\d{2}:\d{2})/);
  return m ? `${m[2]}.${m[1]} ${m[3]}` : (value || "");
}


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


    img.addEventListener("error", () => img.remove());
    ava.appendChild(img);
  }

  const mail = document.createElement("span");
  mail.className = "who__mail";
  mail.textContent = email;

  box.append(ava, mail);


  if (row.original && row.original !== email) {
    const was = document.createElement("span");
    was.className = "who__was";
    was.textContent = `загружено как ${row.original}`;
    was.title = "Очистка изменила строку. Проверен адрес сверху.";
    box.appendChild(was);
  }
  return box;
}


const SOURCE_TEXT = {
  "файл": "из файла — факт",
  "домен": "по домену — факт",
  "адрес": "из самого адреса — факт",
  "разбор": "склеено сегментатором — догадка",
  "профиль": "из публичного профиля — факт",
  "Gravatar": "из профиля Gravatar",
  "имя": "угадано по имени — догадка",
};

function sourceNote(value) {
  if (!value) return "";
  return SOURCE_TEXT[value] || value;
}

function detailRow(row, columns) {
  const tr = document.createElement("tr");
  tr.className = "detail";
  const td = document.createElement("td");
  td.colSpan = columns;

  const more = row.more || {};
  const grid = document.createElement("div");
  grid.className = "detail__grid";

  const pairs = [
    ["Загружено как", row.original],
    ["Проверен как", more.checked_as],
    ["Почтовый сервер", more.mx],
    ["Тип домена", more.domain_type],
    ["Провайдер", more.provider_type],
    ["Грейд", more.grade],
    ["Компания", more.company, more.company_source],
    ["Должность", more.job_role, more.job_role_source],
    ["Имя", [more.first_name, more.last_name].filter(Boolean).join(" ") || row.name,
     more.name_source],
    ["Пол", row.gender, more.gender_source],
    ["Страна", row.country, more.country_source],
    ["Год рождения", more.birth_year],
    ["Соцсети", more.social],
    ["Основание вердикта", row.basis],
  ];

  for (const [label, value, source] of pairs) {
    if (!value && value !== 0) continue;
    const cell = document.createElement("div");
    cell.className = "detail__item";
    const dt = document.createElement("b");
    dt.textContent = label;
    const dd = document.createElement("span");
    dd.textContent = String(value);
    cell.append(dt, dd);
    const note = sourceNote(source);
    if (note) {
      const src = document.createElement("i");


      src.className = "detail__src" + (source === "имя" ? " detail__src--guess" : "");
      src.textContent = note;
      cell.appendChild(src);
    }
    grid.appendChild(cell);
  }

  if (more.pending) {


    const note = document.createElement("p");
    note.className = "detail__note";
    note.textContent = "Адрес из загруженной базы, проверки по нему ещё не было: "
      + "вердикт, скор и ответ сервера появятся здесь, когда движок до него "
      + "дойдёт. В «Сохранить» и «Копировать» такие строки не попадают.";
    grid.appendChild(note);
  }
  if (more.ai_note) {
    const note = document.createElement("p");
    note.className = "detail__note";
    note.textContent = `Замечание модели: ${more.ai_note}`;
    grid.appendChild(note);
  }
  if (more.from_cache) {
    const note = document.createElement("p");
    note.className = "detail__note";
    note.textContent = "Вердикт взят из прошлого прогона — сервер сейчас не "
      + "спрашивали. Дата в колонке «Когда» исходная.";
    grid.appendChild(note);
  }
  if (more.suggested_email) {


    const note = document.createElement("p");
    note.className = "detail__note";
    const живой = more.suggested_status === "valid"
      || more.suggested_status === "catchall";
    note.textContent = живой
      ? `Похоже на опечатку: на ${more.suggested_email} такой ящик есть. `
        + "Проверяли и хороним МЫ ЗАГРУЖЕННЫЙ адрес — решение за вами."
      : `Проверили и похожий адрес ${more.suggested_email} — там тоже `
        + "ничего (" + (more.suggested_status || "без ответа") + ").";
    grid.appendChild(note);
  }
  if (more.typo_of) {


    const note = document.createElement("p");
    note.className = "detail__note";
    note.textContent = `Домен похож на опечатку ${more.typo_of}, а почтовый `
      + "сервер у него есть — такие домены часто ловят чужие письма. Статус "
      + "не меняли; скрыть такие адреса можно галочкой «Без доменов-опечаток».";
    grid.appendChild(note);
  }
  if (!grid.childElementCount) {
    const note = document.createElement("p");
    note.className = "detail__note";
    note.textContent = "Про этот адрес ничего сверх таблицы не известно.";
    grid.appendChild(note);
  }

  td.appendChild(grid);
  tr.appendChild(td);
  return tr;
}


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


function pagerCount(data) {
  const n = Number(data.total) || 0;
  const parts = [`${num(n)} ${plural(n, "адрес", "адреса", "адресов")} в выборке`];
  if (data.pending) parts.push(`без вердикта ${num(data.pending)}`);
  if (ui.base && ui.base.loading) {
    const read = Number(ui.base.total) || 0;
    parts.push(`читаю базу: ${num(read)} ${plural(read, "строка", "строки", "строк")}…`);
  }
  return parts.join(" · ");
}


function emptyText() {
  const base = ui.base || {};
  if (base.loading) return ["Читаю базу…", "Строки появятся здесь, как только лягут в таблицу"];
  if (base.total) {
    return ["В выборке пусто",
            ui.groups.includes("pending")
              ? "Ни одна строка не проходит отбор — сбросьте фильтры"
              : "Отметьте «Не проверены», чтобы увидеть загруженную базу"];
  }
  return ["Здесь появится загруженная база",
          "Загрузите базу — строки покажутся сразу, а вердикты встанут по ходу проверки"];
}

let lastRowsSig = "";

function renderRows(data) {
  const body = $("#gridBody");
  const empty = $("#gridEmpty");


  const sig = JSON.stringify(data.rows);
  const same = sig === lastRowsSig;
  lastRowsSig = sig;

  if (!data.rows.length) {
    if (!same) body.replaceChildren();
    const [title, text] = emptyText();


    setText($("#gridEmpty > b"), title);
    setText($("#gridEmpty > span"), text);
    empty.hidden = false;
    setText($("#pageLabel"), "Стр. 1 / 1");
    setText($("#pageCount"), ui.base && ui.base.loading ? pagerCount(data) : "");
    return;
  }
  empty.hidden = true;
  if (same) {
    ui.page = data.page;
    setText($("#pageLabel"), `Стр. ${data.page} / ${data.pages}`);
    setText($("#pageCount"), pagerCount(data));
    $("#pagePrev").disabled = data.page <= 1;
    $("#pageNext").disabled = data.page >= data.pages;
    return;
  }

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
        td.appendChild(badge);


        const conf = typeof row.confidence === "number" ? row.confidence : null;
        if (conf !== null) {
          const mark = document.createElement("i");
          mark.className = "conf " + (conf >= 75 ? "conf--high"
                                    : conf >= 40 ? "conf--mid" : "conf--low");
          mark.textContent = conf;
          td.appendChild(mark);
        }
        td.title = `${VERDICT_FULL[row.group] || row.status} (${row.status})`
          + (conf !== null ? `
Уверенность ${conf}: ${row.basis || ""}` : "");
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


    tr.classList.add("is-openable");
    tr.tabIndex = 0;
    tr.title = "Нажмите, чтобы увидеть всё, что известно об адресе";
    const toggle = () => {
      const open = tr.nextElementSibling
        && tr.nextElementSibling.classList.contains("detail");
      if (open) {
        tr.nextElementSibling.remove();
        tr.classList.remove("is-open");
        ui.opened.delete(row.email);
      } else {
        tr.after(detailRow(row, cells.length));
        tr.classList.add("is-open");


        ui.opened.add(row.email);
      }
    };
    tr.addEventListener("click", toggle);
    tr.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        toggle();
      }
    });

    frag.appendChild(tr);

    if (ui.opened.has(row.email)) {
      tr.classList.add("is-open");
      frag.appendChild(detailRow(row, cells.length));
    }
  }
  body.replaceChildren(frag);

  ui.page = data.page;
  setText($("#pageLabel"), `Стр. ${data.page} / ${data.pages}`);
  setText($("#pageCount"), pagerCount(data));
  $("#pagePrev").disabled = data.page <= 1;
  $("#pageNext").disabled = data.page >= data.pages;
}


let rowsBusy = false;
let rowsAgain = false;
let lastRowsAt = 0;
let lastFacetsAt = 0;
let lastFacetSig = "";


function facetsDue() {
  const sig = JSON.stringify(selection());
  if (sig !== lastFacetSig || !lastFacetsAt) return true;
  return $$(".facet[open]").length > 0 && Date.now() - lastFacetsAt > 4000;
}

async function refreshRows(force = false) {
  if (ui.tab !== "results") return;
  const sig = JSON.stringify(selection({ page: ui.page }));
  if (!force && sig === ui.lastSig && !ui.running) return;
  if (rowsBusy) { rowsAgain = true; return; }
  rowsBusy = true;
  try {
    ui.lastSig = sig;
    lastRowsAt = Date.now();
    renderRows(await api("page", selection({ page: ui.page })));
    if (facetsDue()) {
      lastFacetSig = JSON.stringify(selection());
      lastFacetsAt = Date.now();
      await refreshFacets();
    }
  } finally {
    rowsBusy = false;
    if (rowsAgain) { rowsAgain = false; refreshRows(true); }
  }
}


let tableSig = "";
let tableTimer = null;
function scheduleTable(s) {
  if (ui.tab !== "results" || tableTimer) return;
  const b = s.base || {};
  const c = s.counts || {};


  const sig = [s.state, c.total, c.valid, c.invalid, c.spam, c.unknown,
               b.total, b.pending, b.loading].join("|");
  if (sig === tableSig) return;
  const busy = s.running || b.loading;
  const wait = busy ? Math.max(0, 1500 - (Date.now() - lastRowsAt)) : 0;
  tableTimer = setTimeout(() => {
    tableTimer = null;
    tableSig = sig;
    refreshRows(true);
  }, wait);
}


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

  const any = ui.search || ui.minScore || ui.hideTypo ||
    Object.values(ui.facets).some((set) => set.size > 0);
  show($("#resetFilters"), !!any);
}

function resetFacets() {
  for (const set of Object.values(ui.facets)) set.clear();
  ui.search = "";
  ui.minScore = 0;
  ui.hideTypo = false;
  $("#search").value = "";
  $("#minScore").value = 0;
  $("#hideTypo").checked = false;
  show($("#searchClear"), false);
  ui.page = 1;
  refreshRows(true);
}


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


const STATE_TEXT = {
  idle: "Готов к работе", running: "Идёт проверка",
  paused: "Пауза", done: "Проверка завершена",
};

const PARSER_STATE_TEXT = {
  idle: "Готов к работе", running: "Идёт сбор",
  paused: "Пауза", done: "Сбор завершён",
};


function syncRunState() {
  const parserMode = ui.mode === "parser";
  const state = parserMode ? (parser.state || "idle") : (ui.state || "idle");
  const badge = $("#runState");
  badge.dataset.state = state;
  setText($("#runStateText"),
          (parserMode ? PARSER_STATE_TEXT : STATE_TEXT)[state] || state);
}

let lastProxySig = "";


let missed = 0;
let skip = 0;

let logSeen = 0;
let lastStateOk = Date.now();


let halted = false;
function quench(on) {
  halted = !!on;
  document.documentElement.classList.toggle("is-halted", halted);
}


let tickBusy = false;
async function tick() {
  if (tickBusy) return;
  tickBusy = true;
  try { await tickOnce(); } finally { tickBusy = false; }
}

async function tickOnce() {
  if (halted) return;
  if (skip > 0) { skip -= 1; return; }
  let s;
  try {
    s = await api("state", { logSince: logSeen });
  } catch {
    if (halted) return;
    missed += 1;
    skip = Math.min(8, missed);
    renderNoLink("live", lastStateOk);
    return;
  }

  if (halted) return;
  missed = 0;
  lastStateOk = Date.now();

  ui.running = s.running;

  ui.state = s.state;
  syncRunState();
  renderLive("live", s.activity);

  setText($("#statValid"),   num(s.counts.valid));
  setText($("#statInvalid"), num(s.counts.invalid));
  setText($("#statUnknown"), num(s.counts.unknown));
  setText($("#statTotal"),   num(s.counts.total));
  setText($("#statSpam"),    num(s.counts.spam));
  setText($("#statNames"),   num(s.counts.names));

  const { current, total, pct } = s.progress;
  const px = s.proxyProgress || { checked: 0, seen: 0, running: false };
  if (px.running) {


    setText($("#progressLabel"),
      `Проверяю прокси: ${num(px.checked)} · прочитано ${num(px.seen)}, файл ещё читается`);
    setText($("#progressPct"), "");
    $("#progressBar").style.width = "0%";
    $("#progressWrap").classList.remove("is-done");

    $("#progressTrack").classList.add("is-running");
  } else {


    const phase = s.phase || {};
    setText($("#progressLabel"),
      phase.name === "retry"
        ? `Перепроверка отложенных: ${num(phase.count)} — им нужен другой выход или выдержка`
        : total
          ? `Проверено адресов: ${num(current)} из ${num(total)}`
          : "Проверка ещё не запускалась");
    setText($("#progressPct"), `${pct}%`);
    $("#progressTrack").classList.remove("is-running");
    $("#progressBar").style.width = `${pct}%`;
    $("#progressWrap").classList.toggle("is-done", pct === 100 && total > 0);
  }

  appendLog(s.log);
  if (typeof s.logSeq === "number") logSeen = Math.max(logSeen, s.logSeq);
  setText($("#logNote"), s.dropped ? `строк лога пропущено: ${num(s.dropped)}` : "");

  const active = s.state === "running" || s.state === "paused";
  show($("#runControls"), active);
  show($("#btnStart"), !active);


  ui.engineBusy = !!s.engineBusy;
  $("#btnStart").disabled = s.running || ui.engineBusy
    || $("#startHint").classList.contains("is-ready") === false;
  setText($("#btnPause"), s.state === "paused" ? "Продолжить" : "Пауза");


  syncLock();

  if (s.proxy) {
    const sig = JSON.stringify(s.proxy).slice(0, 200);
    if (sig !== lastProxySig) { lastProxySig = sig; renderProxy(s.proxy); }
  }


  ui.base = s.base || null;


  scheduleTable(s);
}


function bindDrop(dropId, kind) {
  const el = $(dropId);
  el.addEventListener("click", async () => {


    try {
      const data = await api("choose", { kind });
      showSources(data);
      if (data.error) toast(data.error, "bad");
    } catch (err) {
      const текст = (err && err.message) ? err.message : String(err);
      toast("Не удалось выбрать файл: " + текст, "bad");
    }
  });
  el.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); el.click(); }
  });
  el.addEventListener("dragover", (e) => { e.preventDefault(); el.classList.add("is-over"); });
  el.addEventListener("dragleave", () => el.classList.remove("is-over"));
  el.addEventListener("drop", (e) => {
    e.preventDefault();
    el.classList.remove("is-over");


    const file = e.dataTransfer.files && e.dataTransfer.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async () => {


      try {
        const data = await api("paste", { kind, text: String(reader.result || "") });
        showSources(data);


        toast(data.error || `Загружено: ${file.name}`, data.error ? "bad" : "ok");
      } catch (err) {
        const текст = (err && err.message) ? err.message : String(err);
        toast(`Не удалось загрузить ${file.name}: ${текст}`, "bad");
      }
    };
    reader.onerror = () => {


      toast(`Не удалось прочитать ${file.name}`, "bad");
    };
    reader.readAsText(file);
  });
}

bindDrop("#dropEmails", "emails");
bindDrop("#dropProxies", "proxies");

$("#clearEmails").addEventListener("click", async (e) => {
  e.stopPropagation();
  showSources(await api("clear", { kind: "emails" }));
});
$("#clearProxies").addEventListener("click", async (e) => {
  e.stopPropagation();
  showSources(await api("clear", { kind: "proxies" }));
});


const PASTE_FORMATS = {
  emails: {
    title: "Вставьте список адресов",
    hint: "Одна запись в строке. Кроме адреса можно дать имя, пол и страну — " +
          "в любом порядке и любой комбинации; обязателен только адрес. " +
          "Разделитель любой из , ; : | или табуляция, но в одном списке он " +
          "должен быть ОДИН. Пол и страна понимаются и по-русски, и " +
          "по-английски. Первая строка может быть заголовком CSV.",
    placeholder: [
      "ivan@gmail.com",
      "anna@yahoo.com;Анна;Женский;США",
      "Пётр Смирнов;petr@mail.ru;Мужской;Россия",
      "Россия;Мужской;Ольга;olga@outlook.com",
      "sergey@bk.ru;Сергей",
      "США;maria@hotmail.com",
      "maria@yandex.ru;;Женский;Россия",
      "john@aol.com;John Smith;male;USA",
      "nina@list.ru,Нина,Женский",
      "oleg@rambler.ru|Олег|Мужской|Россия",
      "Ivan Petrov <ivan@gmail.com>",
      "иван@почта.рф;Иван",
      "email;name;gender;country",
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


function pasteHintText(kind, spec) {
  const info = sourceInfo && sourceInfo[kind];
  const hidden = info && info.count && sourceText[kind] === null;
  if (!hidden) return spec.hint;
  const where = kind === "emails" ? "Вся база видна во вкладке «Результаты»" : "Список уже подключён";
  return `${spec.hint} Уже загружено: ${linesLabel(info)} — в поле не показаны, чтобы окно не тормозило. ` +
    `${where}; вставленное здесь ДОБАВИТСЯ к ним.`;
}

function openPaste(kind) {
  pasteKind = kind;
  const spec = PASTE_FORMATS[kind] || PASTE_FORMATS.emails;
  setText($("#pasteTitle"), spec.title);
  setText($("#pasteHint"), pasteHintText(kind, spec));
  const area = $("#pasteArea");


  area.value = sourceText[kind] || "";
  area.placeholder = spec.placeholder;
  setText($("#pasteError"), "");
  show($("#pasteError"), false);
  pasteModal.returnValue = "";
  pasteModal.showModal();
}

$("#pasteEmails").addEventListener("click", () => openPaste("emails"));
$("#pasteProxies").addEventListener("click", () => openPaste("proxies"));


pasteModal.querySelector("form").addEventListener("submit", async (event) => {


  if (event.submitter && event.submitter.value === "cancel") return;

  event.preventDefault();
  const text = $("#pasteArea").value;
  if (!text.trim()) {
    setText($("#pasteError"), "Пусто — нечего добавлять.");
    show($("#pasteError"), true);
    return;
  }


  let data;
  try {
    if (sourceText[pasteKind] !== null && sourceText[pasteKind] !== "") {
      await api("clear", { kind: pasteKind });
    }
    data = await api("paste", { kind: pasteKind, text });
  } catch (err) {
    const текст = (err && err.message) ? err.message : String(err);
    setText($("#pasteError"), "Не удалось добавить: " + текст);
    show($("#pasteError"), true);
    return;
  }
  showSources(data);
  if (data.error) {


    setText($("#pasteError"), data.error);
    show($("#pasteError"), true);
    return;
  }
  show($("#pasteError"), false);
  pasteModal.close();
  toast("Список добавлен", "ok");
});


const threads = $("#threads"), timeout = $("#timeout");
threads.addEventListener("input", () => {
  setText($("#threadsOut"), threads.value);
  paintRange(threads);
});
timeout.addEventListener("input", () => {
  setText($("#timeoutOut"), timeout.value);
  paintRange(timeout);
});


const COUNTRY_HINT = {
  accuracy: "имя ставится только когда словарь его подтвердил, страна — только при уверенном распределении (заполнено ~47% против ~70%)",
  coverage: "заполнено почти всегда: ~треть стран догадка, имя может быть склеено сегментатором из чего угодно",
};

function renderCountryHint() {
  setText($("#countryHint"), COUNTRY_HINT[ui.country] || "");
}

$$(".seg__item").forEach((btn) => btn.addEventListener("click", () => {
  $$(".seg__item").forEach((b) => b.classList.remove("is-active"));
  btn.classList.add("is-active");
  ui.country = btn.dataset.country;
  renderCountryHint();
}));

renderCountryHint();


$("#btnStart").addEventListener("click", async () => {
  const payload = {
    threads: Number(threads.value), timeout: Number(timeout.value),
    country: ui.country,


  };
  let res = await api("start", payload);


  if (!res.ok && res.direct) {
    const agreed = window.confirm([
      "Прокси не заданы.",
      "",
      "Проверка пойдёт с ТВОЕГО домашнего IP — почтовые серверы его увидят.",
      "Gmail и Яндекс ответят честно. Yahoo, AOL, Outlook и iCloud почти",
      "наверняка откажут: им нужен адрес с обратным DNS и чистой репутацией.",
      "",
      "Запускать так?",
    ].join("\n"));
    if (!agreed) return;
    payload.allowDirect = true;
    res = await api("start", payload);
  }
  if (!res.ok) { toast(res.error || "Не удалось запустить", "bad"); return; }
  logBox.replaceChildren();
  toast("Проверка запущена", "ok");
});
$("#btnPause").addEventListener("click", () => api("pause"));

async function stopAndReset(button, method) {
  button.disabled = true;

  quench(true);
  let res = null;
  try { res = await api(method); } catch (e) { res = null; }
  if (res && res.ok) { location.reload(); return; }

  quench(false);
  button.disabled = false;
  toast((res && res.error) || "Не удалось остановить — попробуйте ещё раз", "bad");
}
$("#btnStop").addEventListener("click", () => stopAndReset($("#btnStop"), "stop"));


$$("#viewValidator .tab").forEach((tab) => tab.addEventListener("click", () => {
  $$("#viewValidator .tab").forEach((t) => t.classList.remove("is-active"));
  tab.classList.add("is-active");
  ui.tab = tab.dataset.tab;
  $$("#viewValidator .tabpane").forEach((p) =>
    p.classList.toggle("is-active", p.dataset.pane === ui.tab));
  if (ui.tab === "results") refreshRows(true);
}));


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


$$("#filters input").forEach((box) => box.addEventListener("change", () => {
  ui.groups = $$("#filters input:checked").map((b) => b.value);
  if (!ui.groups.length) { box.checked = true; ui.groups = [box.value]; }
  ui.page = 1;
  refreshRows(true);
}));


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


for (const box of $$(".facet")) {
  box.addEventListener("toggle", () => {
    if (!box.open) return;
    lastFacetSig = JSON.stringify(selection());
    lastFacetsAt = Date.now();
    refreshFacets();
  });
}


document.addEventListener("click", (event) => {
  for (const box of $$(".facet[open]")) {
    if (!box.contains(event.target)) box.open = false;
  }
});

$("#hideTypo").addEventListener("change", () => {
  ui.hideTypo = $("#hideTypo").checked;
  ui.page = 1;
  refreshRows(true);
});

$("#minScore").addEventListener("change", () => {
  ui.minScore = Math.max(0, Math.min(100, Number($("#minScore").value) || 0));
  $("#minScore").value = ui.minScore;
  ui.page = 1;
  refreshRows(true);
});

$("#pagePrev").addEventListener("click", () => { ui.page = Math.max(1, ui.page - 1); refreshRows(true); });
$("#pageNext").addEventListener("click", () => { ui.page += 1; refreshRows(true); });


const ONLY_PENDING = "Не проверенные адреса не копируются и не сохраняются — "
  + "вердикта у них нет, и слать им нельзя. Отметьте вердикты.";
const onlyPending = () => ui.groups.length === 1 && ui.groups[0] === "pending";

$("#btnCopy").addEventListener("click", async () => {
  if (onlyPending()) { toast(ONLY_PENDING, "bad"); return; }
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


  const chunk = Math.max(0, Math.floor(Number($("#chunk").value) || 0));
  $("#chunk").value = chunk;
  if (onlyPending()) { toast(ONLY_PENDING, "bad"); return; }
  const res = await api("export", selection({ chunk }));
  if (res.cancelled) return;
  toast(res.ok ? "Сохраняю в фоне — окно не ждёт" : (res.error || "Не удалось"),
        res.ok ? "ok" : "bad");
});

$("#segmentBy").addEventListener("change", async () => {
  const by = $("#segmentBy").value;
  if (!by) return;
  $("#segmentBy").value = "";
  if (onlyPending()) { toast(ONLY_PENDING, "bad"); return; }
  const res = await api("export_segments", selection({ by }));
  if (res.cancelled) return;
  toast(res.ok ? "Раскладываю в фоне — смотрите лог" : (res.error || "Не удалось"),
        res.ok ? "ok" : "bad");
});

$("#copyLog").addEventListener("click", async () => {
  await navigator.clipboard.writeText(logBox.textContent);
  toast("Лог скопирован", "ok");
});


const pLogBox = $("#pLog");

function appendParserLog(lines) {
  if (!lines || !lines.length) return;
  const atBottom = pLogBox.scrollTop + pLogBox.clientHeight >= pLogBox.scrollHeight - 24;
  const frag = document.createDocumentFragment();
  for (const line of lines) frag.appendChild(logSpan(line));
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


  let data;
  try {
    data = await api("parser_page", { page: parser.page });
  } catch (err) {
    reportClientCrash(err && err.message ? err.message : String(err),
      "refreshFound: не удалось получить страницу найденных адресов",
      err && err.stack);
    return;
  }
  if (force || data.total !== parser.total) {
    parser.total = data.total;
    renderFound(data);
  }
}

let enginesFilled = false;

let parserMissed = 0;
let parserSkip = 0;
let lastParserOk = Date.now();


let parserBusy = false;
async function parserTick() {
  if (parserBusy) return;
  parserBusy = true;
  try { await parserTickOnce(); } finally { parserBusy = false; }
}

async function parserTickOnce() {
  if (halted) return;
  if (parserSkip > 0) { parserSkip -= 1; return; }
  let s;
  try {
    s = await api("parser_state");
  } catch {
    if (halted) return;
    parserMissed += 1;
    parserSkip = Math.min(8, parserMissed);
    renderNoLink("pLive", lastParserOk);
    return;
  }

  if (halted) return;
  parserMissed = 0;
  lastParserOk = Date.now();
  renderLive("pLive", s.activity);

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


  parser.engineBusy = !!s.engineBusy;
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
  $("#pBtnStart").disabled = s.running || parser.engineBusy ||
    $("#pStartHint").classList.contains("is-ready") === false;

  if (parser.tab === "found") await refreshFound();
}

/* ── обработчики второго экрана ── */

bindDrop("#dropDorks", "dorks");
bindDrop("#dropPproxy", "pproxy");

$("#clearDorks").addEventListener("click", async (e) => {
  e.stopPropagation();
  showSources(await api("clear", { kind: "dorks" }));
});
$("#clearPproxy").addEventListener("click", async (e) => {
  e.stopPropagation();
  showSources(await api("clear", { kind: "pproxy" }));
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
$("#pBtnStop").addEventListener("click", () => stopAndReset($("#pBtnStop"), "parser_stop"));

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


function syncLock() {
  setLocked(!!(ui.running || parser.running));
}


[threads, timeout, pThreads, pTimeout].forEach(paintRange);
refreshSources();
tickClocks();
setInterval(tickClocks, 1000);


api("log_tail")
  .then((r) => { appendLog(r.log); logSeen = Math.max(logSeen, r.seq || 0); })
  .catch(() => {})
  .finally(() => { tick(); setInterval(tick, 250); });

api("parser_log_tail").then((r) => appendParserLog(r.log)).catch(() => {}).finally(parserTick);

setInterval(parserTick, 500);
