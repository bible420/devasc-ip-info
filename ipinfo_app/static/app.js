// Address Bench page logic. API data is only ever written with textContent, so
// a provider's response can't inject HTML into the page.
"use strict";

const $ = (id) => document.getElementById(id);

const DETAIL_ROWS = [
  ["Version", (r) => r.analysis.version && `IPv${r.analysis.version}`],
  ["Scope", (r) => r.analysis.scope],
  ["Expanded", (r) => (r.analysis.version === 6 ? r.analysis.expanded : null)],
  ["Reverse DNS", (r) => r.analysis.reverse_dns_name],
  ["ISP", (r) => r.details.isp],
  ["ASN", (r) => r.details.asn],
  ["Network", (r) => r.details.network],
  ["City", (r) => r.details.city],
  ["Region", (r) => r.details.region],
  ["Country", (r) => r.details.country],
  ["Latitude", (r) => r.details.latitude],
  ["Longitude", (r) => r.details.longitude],
  ["Time zone", (r) => r.details.timezone],
  ["Data source", (r) => r.source],
];

const FIELD_NAMES = {
  isp: "ISP",
  asn: "ASN",
  network: "Network",
  city: "City",
  region: "Region",
  country_code: "Country",
  timezone: "Time zone",
};

const STATUS_TEXT = { match: "Match", differs: "Differs", partial: "One source" };

const state = {
  selected: "4",
  payloads: {},
  lookupIp: null,
  loadId: 0,
};

function isMasked() {
  return $("mask-toggle").checked;
}

function make(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

async function getJson(url) {
  const response = await fetch(url);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "The request failed.");
  return data;
}

function setPort(key, status, text) {
  const port = $(key === "lookup" ? "port-lookup" : `port-${key}`);
  port.dataset.state = status;
  port.querySelector(".port-state").textContent = text;
}

function selectPort(key) {
  state.selected = key;
  document.querySelectorAll(".port").forEach((port) => {
    port.setAttribute("aria-pressed", String(port.dataset.port === key));
  });
  resetCrosscheck();
  render();
}

// ----- Bit view -----

function legendItem(className, text) {
  const item = make("li");
  item.append(make("span", `bit ${className}`), document.createTextNode(text));
  return item;
}

function groupValue(bits, version) {
  if (bits.includes("x")) return version === 4 ? "xxx" : "xxxx";
  const value = parseInt(bits, 2);
  return version === 4 ? String(value) : value.toString(16).padStart(4, "0");
}

function renderBits(payload) {
  const container = $("bits");
  const legend = $("legend");
  container.replaceChildren();
  legend.replaceChildren();
  $("anatomy-unit").hidden = !payload || !payload.bits;
  if (!payload || !payload.bits) return;

  const version = payload.report.analysis.version;
  const prefix = payload.prefix_length;
  const total = version === 4 ? 32 : 128;
  container.className = `bits v${version}`;
  container.setAttribute(
    "aria-label",
    `${total}-bit address shown as lights.` +
      (prefix === null ? "" : ` The first ${prefix} bits are the network, the rest are the host.`)
  );

  let index = 0;
  payload.bits.forEach((group) => {
    const wrapper = make("div");
    const leds = make("div", "group-leds");
    for (const bit of group) {
      let zone = "unknown";
      if (bit === "x") zone = "hidden-bit";
      else if (prefix !== null) zone = index < prefix ? "network" : "host";
      const led = make("span", `bit ${zone}${bit === "1" ? " one" : ""}`);
      if (index === prefix && prefix > 0) led.classList.add("boundary");
      led.style.animationDelay = `${index * (version === 4 ? 14 : 4)}ms`;
      leds.append(led);
      index += 1;
    }
    wrapper.append(leds, make("p", "group-value", groupValue(group, version)));
    container.append(wrapper);
  });

  if (prefix !== null) {
    legend.append(
      legendItem("network one", `Network: first ${prefix} bits`),
      legendItem("host one", `Host: last ${total - prefix} bits`)
    );
  } else {
    legend.append(legendItem("unknown one", "Lit = 1, unlit = 0"));
  }
  if (payload.masked) legend.append(legendItem("hidden-bit", "Hidden"));
}

// ----- Page content -----

function summaryText(report) {
  const parts = [];
  if (report.analysis.scope) parts.push(`${report.analysis.scope} address`);
  if (report.details.isp) parts.push(report.details.isp);
  if (report.details.asn) parts.push(report.details.asn);
  if (report.details.country) parts.push(report.details.country);
  return parts.join(" · ");
}

function render() {
  const payload = state.payloads[state.selected];
  const report = payload && payload.report;

  $("copy-ticket").disabled = !report || !report.available;
  $("crosscheck").disabled = !report || !report.available || report.analysis.scope !== "global";
  $("details").replaceChildren();
  renderBits(payload);

  if (!report) {
    $("address").textContent = "Checking";
    $("summary").textContent = "";
    $("notes").textContent = "";
    return;
  }

  $("address").textContent = report.available ? report.address : "Not available";
  $("summary").textContent = report.available ? summaryText(report) : report.label;
  $("notes").textContent = report.notes.join(" ");

  if (report.available) {
    DETAIL_ROWS.forEach(([label, read]) => {
      const value = read(report);
      if (value === null || value === undefined || value === "") return;
      $("details").append(make("dt", "", label), make("dd", "", String(value)));
    });
  } else {
    $("details").append(make("dt", "", "Status"), make("dd", "", "No address detected"));
  }
}

async function loadOwn(version) {
  const key = String(version);
  const loadId = state.loadId;
  delete state.payloads[key];
  setPort(key, "checking", "Checking");
  if (state.selected === key) render();
  try {
    const payload = await getJson(`/api/detect?version=${version}&mask=${isMasked() ? 1 : 0}`);
    if (loadId !== state.loadId) return;
    state.payloads[key] = payload;
    const up = payload.report.available;
    setPort(key, up ? "up" : "down", up ? "Link up" : "No link");
  } catch (error) {
    if (loadId !== state.loadId) return;
    setPort(key, "down", "Error");
    state.payloads[key] = {
      report: { available: false, label: `Public IPv${version}`, notes: [error.message], analysis: {}, details: {} },
      bits: null,
    };
  }
  if (state.selected === key) render();
}

function loadAll() {
  state.loadId += 1;
  resetCrosscheck();
  return Promise.all([loadOwn(4), loadOwn(6)]);
}

async function runLookup(ip) {
  $("lookup-error").textContent = "";
  try {
    const payload = await getJson(`/api/lookup?ip=${encodeURIComponent(ip)}`);
    state.payloads.lookup = payload;
    state.lookupIp = payload.report.address;
    const port = $("port-lookup");
    port.hidden = false;
    setPort("lookup", "up", payload.report.address);
    selectPort("lookup");
  } catch (error) {
    $("lookup-error").textContent = error.message;
  }
}

// ----- Provider cross-check -----

function resetCrosscheck() {
  $("crosscheck-intro").hidden = false;
  $("crosscheck-intro").textContent =
    "Ask both providers about this address and see where they disagree. This uses extra API quota, so it only runs when you ask.";
  $("crosscheck-distance").hidden = true;
  $("crosscheck-table").hidden = true;
}

function renderCrosscheck(result) {
  const differs = result.rows.filter((row) => row.status === "differs").length;
  $("crosscheck-intro").hidden = false;
  if (result.providers.length < 2) {
    const failed = result.failed.join(", ") || "A provider";
    $("crosscheck-intro").textContent = `Can't compare: ${failed} did not respond. Try again later.`;
  } else {
    $("crosscheck-intro").textContent =
      differs === 0
        ? "The providers agree on every field they both returned."
        : `The providers disagree on ${differs} of ${result.rows.length} fields. Confirm these before relying on them.`;
  }

  const distance = $("crosscheck-distance");
  distance.hidden = result.distance_km === null;
  if (result.distance_km !== null) {
    distance.replaceChildren(
      make("b", "", `${result.distance_km.toLocaleString()} km`),
      document.createTextNode(" between the locations they report")
    );
  }

  $("crosscheck-table").hidden = result.providers.length === 0;
  const head = $("crosscheck-head");
  head.replaceChildren(make("th", "", "Field"));
  result.providers.forEach((name) => head.append(make("th", "", name)));
  head.append(make("th", "", "Result"));

  const body = $("crosscheck-body");
  body.replaceChildren();
  result.rows.forEach((row) => {
    const tr = make("tr", row.status);
    tr.append(make("td", "", FIELD_NAMES[row.field] || row.field));
    result.providers.forEach((name) => {
      const value = row.values[name];
      tr.append(make("td", "value", value === null || value === undefined ? "-" : String(value)));
    });
    tr.append(make("td", `status ${row.status}`, STATUS_TEXT[row.status]));
    body.append(tr);
  });
}

async function runCrosscheck() {
  const selected = state.selected;
  const button = $("crosscheck");
  const query =
    selected === "lookup"
      ? `ip=${encodeURIComponent(state.lookupIp)}`
      : `version=${selected}&mask=${isMasked() ? 1 : 0}`;
  button.disabled = true;
  button.textContent = "Checking";
  try {
    const result = await getJson(`/api/crosscheck?${query}`);
    if (state.selected === selected) renderCrosscheck(result);
  } catch (error) {
    if (state.selected === selected) $("crosscheck-intro").textContent = error.message;
  }
  button.textContent = "Run check";
  button.disabled = false;
}

// ----- Copy for ticket -----

function ticketText(report) {
  const lines = [`${report.label}: ${report.address}`];
  DETAIL_ROWS.forEach(([label, read]) => {
    const value = read(report);
    if (value !== null && value !== undefined && value !== "") lines.push(`${label}: ${value}`);
  });
  lines.push(...report.notes.map((note) => `Note: ${note}`));
  return lines.join("\n");
}

async function copyTicket() {
  const button = $("copy-ticket");
  const report = state.payloads[state.selected].report;
  try {
    await navigator.clipboard.writeText(ticketText(report));
    button.textContent = "Copied";
  } catch {
    button.textContent = "Copy failed";
  }
  setTimeout(() => {
    button.textContent = "Copy for ticket";
  }, 1500);
}

// ----- Start -----

document.querySelectorAll(".port").forEach((port) => {
  port.addEventListener("click", () => selectPort(port.dataset.port));
});
$("mask-toggle").addEventListener("change", loadAll);
$("crosscheck").addEventListener("click", runCrosscheck);
$("copy-ticket").addEventListener("click", copyTicket);
$("lookup-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const ip = $("lookup-input").value.trim();
  if (ip) runLookup(ip);
  else $("lookup-error").textContent = "Enter an IP address.";
});

loadAll();
const startIp = new URLSearchParams(window.location.search).get("ip");
if (startIp) {
  $("lookup-input").value = startIp;
  runLookup(startIp);
}
