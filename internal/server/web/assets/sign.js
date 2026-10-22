"use strict"

// The dashboard opens /sign?origin=…&ticket=…[&ticket=…] in a popup, one ticket per document. The tickets are moved
// to sessionStorage and removed from the address bar, so they do not stay in the history.
const MAX_TICKETS = 10
const params = new URLSearchParams(location.search)
if (params.has("ticket")) {
  sessionStorage.setItem("tickets", JSON.stringify([...new Set(params.getAll("ticket"))]))
  sessionStorage.setItem("origin", params.get("origin") || "")
  history.replaceState(null, "", "/sign")
}
const tickets = readTickets()
const origin = sessionStorage.getItem("origin") || ""

const $ = (id) => document.getElementById(id)

// Without CSS masking the PIN would show in clear, so fall back to a password field.
if (!CSS.supports("-webkit-text-security", "disc")) $("pin").type = "password"

const sections = ["loading", "fatal", "form", "working", "done"]
let pollTimer = 0
/** Status polls in a row that got no answer from the agent. */
let unanswered = 0
let signing = false
/** Every document of the link, in order: { ticket, job } or { ticket, error }. */
let docs = []
/** Tickets the PIN form signs. */
let pending = []
/** When the first of the pending jobs expires by this computer's clock (ms since the epoch), Infinity when unknown. */
let deadline = Infinity
/** Whether the agent is asking the backend if the pending jobs expired. */
let checkingExpiry = false
/** What happened to each ticket: { status, error }. */
const outcome = new Map()
let signer = ""
/** The PIN this browser asked the agent to remember, { signer, expires }, or null. The page never sees the PIN. */
let remembered = null
/** How long the agent remembers a PIN on request, 0 when it does not offer to. */
let rememberMinutes = 0

function readTickets() {
  try {
    const list = JSON.parse(sessionStorage.getItem("tickets") || "[]")
    return Array.isArray(list) ? list.filter((t) => typeof t === "string") : []
  } catch {
    return []
  }
}

function show(id) {
  for (const s of sections) $(s).hidden = s !== id
}

/** Tells the dashboard what happened; the dashboard also polls its backend, so this is only a shortcut. */
function notify(status, detail) {
  try {
    if (window.opener && origin) window.opener.postMessage({ type: "pn-esign", status, detail }, origin)
  } catch {
    // The opener navigated away or is cross-origin isolated: polling covers it.
  }
}

async function api(path, body) {
  let res
  try {
    res = await fetch(path, {
      method: body ? "POST" : "GET",
      headers: { "X-PN-eSign": "1", ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      cache: "no-store",
    })
  } catch {
    throw Object.assign(new Error("PoliNetwork eSign stopped answering. Start it again, then press Sign."), {
      code: "agent_unreachable",
    })
  }
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw Object.assign(new Error(data.error?.message || res.statusText), data.error || {})
  return data
}

const START_AGAIN = "Close this window and start again from the dashboard."

/** Ends the page on message, followed by hint ("" for none) and, with setup, a link to the dashboard's setup guide. */
function fatal(message, { hint = START_AGAIN, setup = false } = {}) {
  stopPolling()
  $("fatal-message").textContent = message
  $("fatal-hint").textContent = hint
  $("fatal-hint").hidden = !hint
  // origin was accepted by the agent before any error that asks for the setup guide.
  if (setup) $("fatal-setup").href = new URL("/dashboard/esign/setup", origin).href
  $("fatal-setup-row").hidden = !setup
  show("fatal")
  // The control that had the focus is gone: move it to the heading, as the done screen does, so it is announced.
  $("fatal-title").focus()
}

const JOB_ENDED = new Set([
  "ticket_invalid",
  "too_many_tickets",
  "job_expired",
  "job_done",
  "job_cancelled",
  "job_failed",
  "origin_forbidden",
  "signer_mismatch",
])
/** Card errors that signing again from this window cannot fix. */
const TERMINAL = new Set(["pin_locked", "card_untrusted", "middleware_missing", "not_paired", "certificate_not_found"])
/** Errors that need this computer set up: the page links the setup guide. */
const SETUP = new Set(["middleware_missing", "not_paired", "card_untrusted"])
/** Errors whose message already says what to do next. */
const EXPLAINED = new Set(["job_done", "job_cancelled", "document_changed", "job_failed", "pin_locked"])
/** Errors after which the same documents can be signed again: card errors, and a backend that did not answer. */
const RETRYABLE = new Set(["card_removed", "device_error", "no_card", "no_reader", "backend_unreachable"])

/** The page's own words for an expired link, the same however the expiry was noticed. */
const errorText = (error) => (error?.code === "job_expired" ? "This signing link expired." : error?.message)

/** Ends the page on an error that leaves nothing to sign here. */
function fatalError(error) {
  const setup = SETUP.has(error?.code)
  const hint = setup || EXPLAINED.has(error?.code) ? "" : START_AGAIN
  fatal(errorText(error) || "The signature failed.", { hint, setup })
}

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`
const pageList = new Intl.ListFormat("en-GB", { type: "conjunction" })

/** "2 signatures · pages 1 and 3", "1 signature and 1 mark · page 2". */
function plan(job) {
  let what = plural(Math.max(job.signatures || 1, 1), "signature", "signatures")
  if (job.marks > 0) what += ` and ${plural(job.marks, "mark", "marks")}`
  const pages = (job.pages?.length ? job.pages : [job.placement.page]).map((p) => String(p + 1))
  return `${what} · ${pages.length === 1 ? "page" : "pages"} ${pageList.format(pages)}`
}

function titleOf(doc) {
  return doc.job ? doc.job.document.title : `Document ${docs.indexOf(doc) + 1}`
}

function line(parent, text, className) {
  if (!text) return
  const el = document.createElement("span")
  el.textContent = text
  if (className) el.className = className
  parent.append(el)
}

function fillList(list, items, render) {
  list.replaceChildren(
    ...items.map((doc) => {
      const li = document.createElement("li")
      render(li, doc)
      return li
    }),
  )
  list.hidden = items.length === 0
}

function describeDoc(li, doc) {
  const title = document.createElement("strong")
  title.textContent = titleOf(doc)
  li.append(title)
  if (!doc.job) {
    li.classList.add("failed")
    line(li, errorText(doc.error), "bad")
    return
  }
  const by = [doc.job.requestedBy && `Requested by ${doc.job.requestedBy}`, doc.job.signer.role].filter(Boolean)
  line(li, by.join(" · "), "muted")
  line(li, plan(doc.job))
}

function describeResult(li, doc) {
  const result = outcome.get(doc.ticket) || { status: "skipped" }
  const mark = document.createElement("span")
  mark.className = result.status === "completed" ? "mark ok" : "mark bad"
  mark.textContent = result.status === "completed" ? "✓" : "✕"
  mark.setAttribute("aria-hidden", "true")
  const text = document.createElement("div")
  const title = document.createElement("strong")
  title.textContent = titleOf(doc)
  text.append(title)
  if (result.status === "completed") line(text, "Signed", "ok")
  else if (result.status === "skipped") line(text, "Not signed", "bad")
  else line(text, errorText(result.error) || "Not signed", "bad")
  li.classList.add("result")
  li.append(mark, text)
}

async function load() {
  if (!tickets.length || !origin) return fatal("This page needs a signing link from the dashboard.")
  if (tickets.length > MAX_TICKETS) return fatal(`Sign at most ${MAX_TICKETS} documents at a time.`)
  if (tickets.length > 1) $("loading-text").textContent = "Loading the documents…"
  try {
    ;({ jobs: docs, remembered, rememberMinutes = 0 } = await api("/api/job", { tickets, origin }))
  } catch (error) {
    return fatal(error.message || "Cannot load the document.")
  }
  for (const doc of docs) if (!doc.job) outcome.set(doc.ticket, { status: "failed", error: doc.error })
  const ready = docs.filter((d) => d.job)
  if (!ready.length) {
    if (docs.length === 1) return fatalError(docs[0].error)
    fillList($("fatal-docs"), docs, describeDoc)
    return fatal("None of these documents can be signed.")
  }
  showForm(docs, ready.map((d) => d.ticket))
}

/** Shows the PIN form for the tickets to sign, listing the given documents. */
function showForm(listed, toSign, message = "") {
  pending = toSign
  // Go sends a missing time as year 1.
  const expiries = docs.filter((d) => pending.includes(d.ticket)).map((d) => Date.parse(d.job.expiresAt))
  deadline = Math.min(...expiries.filter((t) => t > 0))
  const several = docs.length > 1
  const n = pending.length
  $("facts").hidden = several
  if (several) {
    $("heading").textContent = `Sign ${plural(n, "document", "documents")}`
    fillList($("docs"), listed, describeDoc)
    document.title = `Sign ${plural(n, "document", "documents")} · PoliNetwork`
  } else {
    const { job } = docs[0]
    $("heading").textContent = job.document.title
    $("doc-file").textContent = job.document.fileName
    $("doc-place").textContent = plan(job)
    $("doc-requester").textContent = job.requestedBy || ""
    $("doc-requester-row").hidden = !job.requestedBy
    $("doc-signer").textContent = job.signer.role ? `${job.signer.name} · ${job.signer.role}` : job.signer.name
    $("docs").hidden = true
    document.title = `Sign “${job.document.title}” · PoliNetwork`
  }
  $("submit").textContent = n === 1 ? "Sign" : `Sign ${n} documents`
  $("pin").value = ""
  $("remember").checked = false
  formError(message)
  show("form")
  showPIN()
  startPolling()
}

const timeFormat = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" })

/** Shows the PIN field, or that the agent remembers the PIN, and moves the focus to what comes next. */
function showPIN() {
  const known = Boolean(remembered)
  $("remembered").hidden = !known
  $("pin-fields").hidden = known
  if (known) {
    const until = timeFormat.format(new Date(remembered.expires))
    $("remembered-text").textContent =
      `Your PIN is remembered${remembered.signer ? ` for ${remembered.signer}` : ""} until ${until}, while the CIE stays on the reader.`
    $("submit").focus()
  } else {
    $("remember-row").hidden = !rememberMinutes
    $("remember-text").textContent = `Remember the PIN on this computer for ${rememberMinutes} minutes`
    $("pin").focus()
  }
}

/** Updates what the agent remembers from a status, and asks for the PIN when the agent forgot it meanwhile. */
function setRemembered(next) {
  const was = Boolean(remembered)
  remembered = next || null
  if (was === Boolean(remembered) || $("form").hidden) return
  showPIN()
  if (was) formError("The remembered PIN was forgotten: the CIE left the reader or the time ran out.")
}

function startPolling() {
  stopPolling()
  pollStatus()
  pollTimer = setInterval(pollStatus, 1500)
}

function stopPolling() {
  clearInterval(pollTimer)
}

/** How long the PIN form stays before asking the backend again whether the pending jobs expired. */
const EXPIRY_RECHECK = 30_000

/**
 * Once this computer's clock says a pending job expired, asks the backend, which decides: a clock running fast must
 * not end the window early. Shows the expiry screen only when the backend confirms, without cancelling the jobs (the
 * dashboard then says they expired); otherwise asks again later. A signature already running is left to finish.
 */
async function checkExpiry() {
  if (signing || checkingExpiry || $("form").hidden || Date.now() < deadline) return
  checkingExpiry = true
  let jobs = []
  try {
    ;({ jobs = [] } = await api("/api/job", { tickets: pending, origin }))
  } catch {
    // Neither the agent nor the backend says the jobs expired: ask again later.
  }
  checkingExpiry = false
  if (signing || $("form").hidden) return
  if (jobs.some((d) => pending.includes(d.ticket) && d.error?.code === "job_expired")) {
    notify("error", "job_expired")
    fatalError({ code: "job_expired" })
    return
  }
  deadline = Date.now() + EXPIRY_RECHECK
}

async function pollStatus() {
  if (signing) return
  checkExpiry()
  const card = $("card")
  let status
  try {
    status = await api("/api/status")
  } catch (error) {
    if (error.code === "agent_unreachable" && ++unanswered >= 3) {
      card.dataset.state = "waiting"
      $("card-text").textContent = "PoliNetwork eSign stopped answering. Start it again."
    }
    return
  }
  unanswered = 0
  if (status.busy) return
  setRemembered(status.remembered)
  const { reader, software } = describeStatus(status)
  card.dataset.state = status.ready ? "ready" : "waiting"
  if (status.ready) $("card-text").textContent = reader?.name ? `Card detected on ${reader.name}` : "Card detected"
  // Unavailable software lists no readers, so it comes first.
  else if (!software.ok) $("card-text").textContent = "No CIE software found. See the setup guide in the dashboard."
  else if (!reader?.ok) $("card-text").textContent = "Connect the NFC card reader"
  else $("card-text").textContent = `Place your CIE on the reader (${reader.name})`
}

function formError(message) {
  $("error").textContent = message
  $("error").hidden = !message
}

/** Documents that failed on a card error and can be signed again with the PIN. */
function retryable() {
  return docs.filter((d) => {
    const r = outcome.get(d.ticket)
    return d.job && r && r.status !== "completed" && RETRYABLE.has(r.error?.code)
  })
}

function showResults() {
  stopPolling()
  const signed = docs.filter((d) => outcome.get(d.ticket)?.status === "completed").length
  const all = signed === docs.length
  const again = retryable()
  notify(all ? "completed" : "error", all ? undefined : docs.map((d) => outcome.get(d.ticket)?.error?.code).find(Boolean))

  if (docs.length === 1) {
    const result = outcome.get(docs[0].ticket)
    if (!all) {
      // One document: an error that retrying can fix goes back to the PIN, anything else ends here, as before.
      if (again.length) return showForm(docs, [docs[0].ticket], result.error.message)
      return fatalError(result.error)
    }
  }

  $("done-icon").textContent = all ? "✓" : "!"
  $("done-icon").classList.toggle("bad", !all)
  if (docs.length === 1) $("done-title").textContent = "Signed"
  else if (all) $("done-title").textContent = docs.length === 2 ? "Both documents signed" : `All ${docs.length} documents signed`
  else $("done-title").textContent = signed ? `${signed} of ${docs.length} signed` : "No documents signed"
  fillList($("results"), docs.length > 1 ? docs : [], describeResult)
  document.title = `${$("done-title").textContent} · PoliNetwork`

  let message = signer ? `Signed as ${signer}.` : ""
  if (all) message += " You can close this window."
  else if (again.some((d) => outcome.get(d.ticket).error.code !== "backend_unreachable"))
    message += " Keep the CIE still on the reader and try again."
  else if (again.length) message += " Try again in a moment."
  else message += " Start again from the dashboard for the others."
  $("done-message").textContent = message.trim()
  $("retry").hidden = again.length === 0
  show("done")
  $("done-title").focus()
  if (all) setTimeout(() => window.close(), 4000)
}

$("form").addEventListener("submit", async (event) => {
  event.preventDefault()
  // Without a PIN the agent uses the one it remembers for this browser.
  const body = { tickets: pending, origin }
  if (!remembered) {
    const pin = $("pin").value.trim()
    if (!/^\d{8}$/.test(pin)) {
      formError(
        /^\d{4}$/.test(pin)
          ? "Type all 8 digits of your CIE PIN. Other CIE apps ask only for the last 4."
          : "Type the 8 digits of your CIE PIN.",
      )
      $("pin").focus()
      return
    }
    body.pin = pin
    body.remember = $("remember").checked
  }
  // Cleared before the form goes away, so a browser watching the submission has nothing to offer to save.
  $("pin").value = ""
  formError("")
  signing = true
  $("working-title").textContent = pending.length === 1 ? "Signing…" : `Signing ${pending.length} documents…`
  show("working")
  let result
  try {
    result = await api("/api/sign", body)
  } catch (error) {
    signing = false
    if (JOB_ENDED.has(error.code) || TERMINAL.has(error.code)) {
      notify("error", error.code)
      return fatalError(error)
    }
    // After a failure the agent no longer remembers the PIN, unless the card was busy and was never tried.
    if (error.code !== "busy") remembered = null
    show("form")
    showPIN()
    $("pin").value = ""
    let message = error.message || "The signature failed."
    if (error.code === "pin_incorrect") {
      message =
        typeof error.retriesLeft === "number"
          ? `Wrong PIN. ${error.retriesLeft} ${error.retriesLeft === 1 ? "attempt" : "attempts"} left before the PIN is blocked.`
          : "Wrong PIN. After 3 wrong attempts the PIN is blocked and needs the PUK."
    }
    formError(message)
    // Asking for the PIN is not a failure of the signature.
    if (error.code !== "pin_required") notify("error", error.code)
    return
  }
  signing = false
  if (result.signer?.displayName) signer = result.signer.displayName
  for (const r of result.results || []) outcome.set(r.ticket, r)
  showResults()
})

$("pin").addEventListener("input", () => {
  $("pin").value = $("pin").value.replace(/\D/g, "").slice(0, 8)
})

$("forget").addEventListener("click", async () => {
  try {
    await api("/api/forget", {})
  } catch {
    // The page asks for the PIN anyway, and typing it replaces the remembered one.
  }
  remembered = null
  formError("")
  showPIN()
})

$("cancel").addEventListener("click", async () => {
  try {
    await api("/api/cancel", { tickets: pending, origin })
  } catch {
    // Closing anyway: the jobs expire on their own.
  }
  notify("cancelled")
  window.close()
})

$("retry").addEventListener("click", () => {
  const again = retryable()
  showForm(again, again.map((d) => d.ticket))
})

for (const button of document.querySelectorAll("[data-close]")) button.addEventListener("click", () => window.close())

// Timers slow down in a covered window or a sleeping laptop: check again as soon as the window shows.
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") checkExpiry()
})

load()
