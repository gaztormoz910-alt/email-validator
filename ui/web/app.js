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

/* ── сбой в самом окне ─────────────────────────────────────────
   Половина случаев «программа сломалась» приходится сюда, а не на питон:
   журнал событий Windows краха процесса не показывал, то есть ломалось
   окно. Консоль WebView2 владельцу не видна, поэтому без этого канала
   такой сбой не оставлял следа вообще нигде.

   Отправка идёт напрямую через fetch, а не через api(): если сломан сам
   api(), сообщение об этом им же и не уедет. И тихо — сбой отчёта о сбое
   не должен порождать второй отчёт, иначе получится вечная петля. */
let crashReports = 0;

function reportClientCrash(message, where, stack) {
  // Потолок на прогон: ошибка в тике повторяется дважды в секунду, и без
  // него журнал за ночь вырастет до гигабайта, а разбирать всё равно будут
  // первую запись.
  if (crashReports >= 20) return;
  crashReports += 1;
  try {
    fetch("/api/client_error", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Token": TOKEN },
      body: JSON.stringify({
        message: String(message || "").slice(0, 500),
        where: String(where || "").slice(0, 300),
        stack: String(stack || "").slice(0, 4000),
      }),
    }).catch(() => {});
  } catch {
    /* отчёт о сбое не имеет права стать вторым сбоем */
  }
}

/* Описать что угодно, ничего не уронив.

   Первая версия этого перехватчика поймала у владельца десять сбоев и
   записала все десять ПУСТЫМИ: она верила, что у события есть message, а у
   причины отказа — понятный вид. Пустая запись стоит ровно столько же,
   сколько её отсутствие, поэтому теперь описывается всё, что удалось
   разглядеть, и всегда остаётся хотя бы вид события. */
function describe(value) {
  if (value === null) return "null";
  if (value === undefined) return "undefined";
  try {
    if (typeof value === "string") return value || "(пустая строка)";
    if (value instanceof Error) {
      return `${value.name}: ${value.message || "(без текста)"}`;
    }
    const text = String(value);
    // "[object Object]" не говорит ничего — тогда показываем поля.
    if (text === "[object Object]") {
      return JSON.stringify(value).slice(0, 400);
    }
    return text || `(пусто, тип ${typeof value})`;
  } catch {
    return `(не удалось описать, тип ${typeof value})`;
  }
}

window.addEventListener("error", (event) => {
  // Ошибка ЗАГРУЗКИ ресурса приходит сюда же, но у неё нет ни message, ни
  // filename — зато есть target. Именно такой случай и записывался пустым.
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
}, true);   // true — иначе ошибки загрузки ресурсов сюда не всплывают

// Отказ обещания, который никто не перехватил, — самый частый вид поломки в
// этом окне: почти вся работа идёт через async-функции.
window.addEventListener("unhandledrejection", (event) => {
  const reason = event.reason;
  reportClientCrash(
    `[отказ обещания] ${describe(reason)}`,
    "необработанный отказ обещания",
    reason && reason.stack);
});

/* ── подавление страницы браузером ─────────────────────────────
   Когда браузер считает страницу невидимой, он зажимает setInterval до
   одного раза в секунду и ПОЛНОСТЬЮ останавливает requestAnimationFrame —
   то есть перестаёт перерисовывать окно. Замерено на живой странице: девять
   тиков за восемь секунд вместо тридцати двух, ноль кадров за тридцать
   секунд, ноль ошибок.

   Клики при этом доходят и обработчики срабатывают, но картинка не
   меняется. Со стороны это неотличимо от «зависло намертво», и ни один
   перехватчик ошибок такого не поймает: ошибки нет.

   WebView2 включает подавление, когда считает окно перекрытым, и ошибается
   в этом известным образом. Лечится ключами запуска (см. webapp.py), но
   сказать об этом всё равно надо: молчаливое подавление владелец читает
   как поломку программы. */
let throttleReported = false;

function onVisibilityChange() {
  if (document.visibilityState === "hidden") {
    if (!throttleReported) {
      throttleReported = true;
      reportClientCrash(
        "[подавление] Браузер считает окно невидимым и душит его: таймеры "
        + "зажаты до одного раза в секунду, отрисовка остановлена. Окно "
        + "выглядит зависшим, хотя ничего не сломалось.",
        "document.visibilityState = hidden");
    }
    return;
  }
  // Видимость вернулась — догоняем НЕМЕДЛЕННО, не дожидаясь тика.
  // Иначе после подавления окно ещё секунду показывает устаревшее
  // состояние, и владелец видит «отвисло не сразу».
  tick();
  parserTick();
  if (ui.tab === "results") refreshRows(true);
  if (parser.tab === "found") refreshFound(true);
}

document.addEventListener("visibilitychange", onVisibilityChange);

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
  // «Точность» по умолчанию: страна проставляется реже, но не выдумывается.
  // Замерено на 1600 частых именах: строгий режим даёт 50.1% верных при 8.7%
  // неверных, «брать лидера всегда» — 66.4% при 33.6% неверных. Плюс
  // шестнадцать пунктов правды стоят плюс двадцати пяти пунктов вымысла.
  country: "accuracy",
  running: false,
  mode: "validator",
  lastSig: "",          // отпечаток выборки: по нему решаем, перезапрашивать ли
  // Адреса с раскрытой карточкой. Множество, а не флаг на строке: строки
  // пересоздаются при каждой перерисовке, а во время прогона она идёт раз
  // в секунду — без этого карточка захлопывалась бы сама собой.
  opened: new Set(),
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

function filesLabel(info) {
  // «источник», а не «файл»: вставленный руками список — тоже источник, и
  // «1 файл · вставленный текст» звучало бы неправдой.
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
    // Главная строка карточки — СКОЛЬКО СТРОК ЗАГРУЖЕНО. Это первое, что
    // владелец хочет знать, и раньше этого не было нигде: в заголовке
    // стояло «13 источника», то есть число ФАЙЛОВ.
    //
    // Имена файлов ушли вниз, в подпись. У заголовка стоит обрезка по
    // ширине (text-overflow: ellipsis), и приписанное к именам число просто
    // не поместилось бы: «test_1.txt, test_base.txt, test…» — и всё.
    setText($(`#${prefix}Title`), info.count ? linesLabel(info) : info.title);
    const hint = $(`#${prefix}Hint`);
    if (info.count) {
      setText(hint, `${filesLabel(info)} · ${info.detail}`);
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

let countPoll = null;

// Единственная дверь для показа источников. Половина путей рисовала карточку
// напрямую ответом от choose/paste/clear и доопрос не заводила — подпись у
// них застревала на «считаю строки…» до следующего действия владельца.
function showSources(data) {
  renderSources(data);
  armCountPoll(data);
  askResume();
  return data;
}

// Есть ли что продолжать по нынешним файлам базы.
//
// Спрашиваем при каждой смене источников: журнал сделанного привязан к
// НАБОРУ файлов, и для другой базы ответ другой. Пока продолжать нечего,
// строка спрятана вовсе — предлагать нажать на пустое незачем.
async function askResume() {
  let done = 0;
  try {
    const info = await api("resume_info");
    done = (info && info.done) || 0;
  } catch (e) {
    done = 0;
  }
  const row = $("#resumeRow");
  if (!row) return;
  // is-folded, а НЕ is-gone: второй прячет через visibility и оставляет
  // дыру в панели. Продолжать бывает нечего почти всегда, и пустой блок
  // висел бы там постоянно — владелец это и увидел.
  row.classList.toggle("is-folded", !done);
  if (!done) {
    $("#optResume").checked = false;
    return;
  }
  setText($("#resumeHint"), `уже проверено по этим файлам: ${num(done)}`);
}

function armCountPoll(data) {

  // Счёт строк идёт в фоне, и его результат приходит ПОСЛЕ этого ответа.
  // Обычный тик страницы опрашивает только состояние прогона, поэтому без
  // повторного запроса подпись навсегда застревала на «считаю строки…» —
  // ровно это и было видно в окне.
  //
  // Опрос самозавершающийся: как только все четыре поля назвали число,
  // он прекращается. Постоянный лишний запрос ради редкого случая не нужен.
  const counting = ["emails", "proxies", "dorks", "pproxy"]
    .some((k) => data[k] && data[k].count && (data[k].lines === null || data[k].lines === undefined));
  clearTimeout(countPoll);
  if (counting) countPoll = setTimeout(refreshSources, 400);
}

async function refreshSources() { showSources(await api("sources")); }

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

  // Что лежало в файле, если очистка адрес изменила.
  //
  // Поле приезжало с сервера и молча выбрасывалось: главное требование
  // владельца — «какие почты загрузил, такие и проверяй» — в окне видно
  // не было вовсе. Показываем ТОЛЬКО когда строки разошлись: подпись под
  // каждым адресом перестала бы что-либо значить.
  if (row.original && row.original !== email) {
    const was = document.createElement("span");
    was.className = "who__was";
    was.textContent = `загружено как ${row.original}`;
    was.title = "Очистка изменила строку. Проверен адрес сверху.";
    box.appendChild(was);
  }
  return box;
}

/* ── карточка адреса ──────────────────────────────────────────
   Движок считает на каждом адресе компанию, должность, тип домена, год
   рождения, грейд и ИСТОЧНИК каждой догадки. В девять колонок это не
   влезает, и раньше всё перечисленное было видно только в выгрузке и в
   консоли — то есть для того, кто работает окном, его как бы не было.

   Карточка раскрывается по клику на строку. Ничего не запрашивает: все
   данные уже приехали вместе со страницей. */

const SOURCE_TEXT = {
  "файл": "из файла — факт",
  "домен": "по домену — факт",
  "адрес": "из самого адреса — факт",
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
      // Догадку помечаем отдельно: «Италия» из файла и «Италия», угаданная
      // по имени, — разные вещи, и выглядеть одинаково они не должны.
      src.className = "detail__src" + (source === "имя" ? " detail__src--guess" : "");
      src.textContent = note;
      cell.appendChild(src);
    }
    grid.appendChild(cell);
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
        td.appendChild(badge);
        // Уверенность в вердикте — рядом со словом, а не вместо него.
        // «Годен» на домене, принимающем что угодно, и «Годен»,
        // подтверждённый контрольной пробой, — это одно слово и разные
        // основания; число показывает разницу, подсказка её объясняет.
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

    // Клик раскрывает карточку под строкой. Вторая строка таблицы, а не
    // всплывающее окно: так видно сразу несколько адресов рядом, и ничего
    // не перекрывает таблицу.
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
        // Запоминаем раскрытые. Во время прогона таблица перерисовывается
        // раз в секунду, и без этого карточка захлопывалась бы ровно тогда,
        // когда за ней и следят.
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
    // Карточка, раскрытая до перерисовки, остаётся раскрытой.
    if (ui.opened.has(row.email)) {
      tr.classList.add("is-open");
      frag.appendChild(detailRow(row, cells.length));
    }
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
    // Знаменателя нет, но работа идёт — и это надо показать.
    $("#progressTrack").classList.add("is-running");
  } else {
    // Перепроверка отложенных — отдельная фаза, и об этом надо сказать.
    // Иначе бар стоит на месте у самого конца, и прогон выглядит зависшим.
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
    showSources(data);
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
      showSources(data);
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
  showSources(await api("clear", { kind: "emails" }));
});
$("#clearProxies").addEventListener("click", async (e) => {
  e.stopPropagation();
  showSources(await api("clear", { kind: "proxies" }));
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
  showSources(data);
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
  const payload = {
    threads: Number(threads.value), timeout: Number(timeout.value),
    ai: $("#optAi").checked, osint: $("#optOsint").checked,
    cache: $("#optCache").checked, country: ui.country,
    resume: $("#optResume").checked,
  };
  let res = await api("start", payload);

  // Прокси не заданы. Прогон возможен, но пойдёт с домашнего адреса
  // владельца, и почтовики его увидят. Спрашиваем прямо, а не запускаем
  // молча и не запрещаем совсем: запрет как раз и приводил к тому, что до
  // проверки почт дело не доходило вовсе.
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
  // Перехват тут обязателен: это единственный вызов в тике сбора, который
  // его не имел, — соседний parser_state обёрнут с самого начала. Отказ
  // уходил в неперехваченное обещание, а окно после этого выглядело
  // сломанным, не сказав ни слова.
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
