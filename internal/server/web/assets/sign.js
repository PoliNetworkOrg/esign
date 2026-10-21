"use strict"

// The dashboard opens /sign?origin=…&ticket=…[&ticket=…] in a popup, one ticket per document. The tickets are moved
// to sessionStorage and removed from the address bar, so they do not stay in the history. The origin stays there, so
// that the agent can check it again when the page is reloaded.
const MAX_TICKETS = 10
const params = new URLSearchParams(location.search)
if (params.has("ticket")) {
  sessionStorage.setItem("tickets", JSON.stringify([...new Set(params.getAll("ticket"))]))
  history.replaceState(null, "", `/sign?${new URLSearchParams({ origin: params.get("origin") || "" })}`)
}
const tickets = readTickets()
const origin = params.get("origin") || ""
/**
 * Where the page's messages go: origin when the agent signs for it, "" otherwise. The agent checked it when serving
 * the page, so even the first message, sent before any request, reaches an allowed dashboard only.
 */
const dashboard = document.documentElement.dataset.dashboard || ""

// First thing, before any request: a window that stays silent tells the dashboard that the agent is not running.
notify("ready", document.documentElement.dataset.version)

const $ = (id) => document.getElementById(id)

// Without CSS masking the PIN would show in clear, so fall back to a password field.
const masking = CSS.supports("-webkit-text-security", "disc")
if (!masking) $("pin").type = "password"

const sections = ["loading", "fatal", "form", "working", "done"]
let pollTimer = 0
/** Status polls in a row that got no answer from the agent. */
let unanswered = 0
let signing = false
/** Every document of the link, in order: { ticket, job } or { ticket, error }. */
let docs = []
/** Tickets the PIN form signs. */
let pending = []
/** Documents the PIN form lists. */
let listed = []
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
/**
 * The PIN attempts left before the card blocks the PIN, { left, card }, as the card reported them (card) or as the
 * agent counted wrong PINs on this computer, even in windows closed since; null when no wrong PIN is on record.
 */
let attempts = null
const lastAttempt = () => attempts !== null && attempts.left <= 1
/**
 * What the agent says about the card: "checking" until it answers, then "present", "absent" (a signature would fail
 * before the PIN is sent) or "unknown" (it cannot tell). The PIN and Sign wait while the card is checked for or absent,
 * so that nobody types a PIN for a card that is not there; "unknown" never holds them back.
 */
let card = "checking"
const cardReady = () => card === "present" || card === "unknown"
/** Answers in a row without the card since the page last saw it. */
let missing = 0
/** A card moving on the reader can drop out of one answer: only this many in a row mean that it was taken away. */
const REMOVED_AFTER = 2

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

/** Sets text only when it changes, so that live regions announce changes and nothing else. */
function setText(el, text) {
  if (el.textContent !== text) el.textContent = text
}

/**
 * Tells the dashboard what happened, with any other fields of the message; the dashboard also polls its backend, so
 * this is only a shortcut.
 */
function notify(status, detail, fields) {
  if (!window.opener || !dashboard) return
  try {
    window.opener.postMessage({ type: "pn-esign", status, detail, ...fields }, dashboard)
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

/**
 * Ends the page on message, followed by hint ("" for none) and, with setup, a link to the dashboard's setup guide or,
 * with download, the download of the newest version. The dashboard learns it as a fatal error with code, so it
 * explains it instead of waiting for the window.
 */
function fatal(message, options = {}) {
  const { code = "internal", title = "Cannot sign", hint = START_AGAIN, setup = false, download = false } = options
  stopPolling()
  notify("error", code, { message, fatal: true })
  $("fatal-title").textContent = title
  $("fatal-message").textContent = message
  $("fatal-hint").textContent = hint
  $("fatal-hint").hidden = !hint
  // origin was accepted by the agent before any error that asks for the setup guide.
  if (setup) $("fatal-setup").href = new URL("/dashboard/esign/setup", origin).href
  $("fatal-setup-row").hidden = !setup
  $("fatal-download").hidden = !download
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

/** Ends the page on a version that the dashboard no longer accepts, offering the one that replaces it. */
function outdated() {
  fatal(`This version is too old to sign. ${$("fatal-download").dataset.update}`, {
    code: "agent_outdated",
    title: "Update PoliNetwork eSign",
    hint: "Then sign again from the dashboard.",
    download: true,
  })
}

/** Ends the page on an error that leaves nothing to sign here. */
function fatalError(error) {
  const setup = SETUP.has(error?.code)
  const hint = setup || EXPLAINED.has(error?.code) ? "" : START_AGAIN
  fatal(errorText(error) || "The signature failed.", { code: error?.code, hint, setup })
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
  // A document that could not be loaded, or whose link expired while the form was open.
  const error = outcome.get(doc.ticket)?.error
  if (!doc.job || error?.code === "job_expired") {
    li.classList.add("failed")
    line(li, errorText(error), "bad")
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
  if (!tickets.length || !origin)
    return fatal("This page needs a signing link from the dashboard.", { code: "ticket_invalid" })
  if (tickets.length > MAX_TICKETS)
    return fatal(`Sign at most ${MAX_TICKETS} documents at a time.`, { code: "too_many_tickets" })
  if (tickets.length > 1) $("loading-text").textContent = "Loading the documents…"
  try {
    ;({ jobs: docs, remembered, rememberMinutes = 0, attempts = null } = await api("/api/job", { tickets, origin }))
  } catch (error) {
    return fatal(error.message || "Cannot load the document.", { code: error.code })
  }
  if (docs.some((d) => d.error?.code === "agent_outdated")) return outdated()
  for (const doc of docs) if (!doc.job) outcome.set(doc.ticket, { status: "failed", error: doc.error })
  const ready = docs.filter((d) => d.job)
  if (!ready.length) {
    if (docs.length === 1) return fatalError(docs[0].error)
    fillList($("fatal-docs"), docs, describeDoc)
    return fatal("None of these documents can be signed.", { code: docs[0].error?.code })
  }
  showForm(docs, ready.map((d) => d.ticket))
}

/** Shows the PIN form for the tickets to sign, listing the given documents. */
function showForm(list, toSign, message = "") {
  setPending(list, toSign)
  $("pin").value = ""
  $("remember").checked = false
  formError(message)
  pinError("")
  show("form")
  showPIN()
  startPolling()
}

/** Sets the tickets that the PIN form signs and the documents it lists, and describes them; the PIN stays. */
function setPending(list, toSign) {
  pending = toSign
  listed = list
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
  } else {
    // The last attempt is no time to remember a PIN that may be wrong.
    $("remember-row").hidden = !rememberMinutes || lastAttempt()
    if (lastAttempt()) $("remember").checked = false
    $("remember-text").textContent = `Remember the PIN on this computer for ${rememberMinutes} minutes`
  }
  const warn = !known && lastAttempt()
  $("last-attempt").hidden = !warn
  $("pin").setAttribute("aria-describedby", warn ? "last-attempt pin-hint" : "pin-hint")
  if (cardReady()) focusNext()
}

/** Moves the focus to what the signer does once the card is there: type the PIN, or press Sign when it is remembered. */
function focusNext() {
  ;(remembered ? $("submit") : $("pin")).focus()
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
 * not end the window early. A job the backend confirms expired leaves the form, which keeps the others, and shows as
 * failed; the expiry screen comes only when none is left. The jobs are not cancelled (the dashboard then says they
 * expired). A signature already running is left to finish.
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
  const expired = jobs.filter((d) => pending.includes(d.ticket) && d.error?.code === "job_expired").map((d) => d.ticket)
  const left = pending.filter((t) => !expired.includes(t))
  if (!left.length) {
    fatalError({ code: "job_expired" })
    return
  }
  if (expired.length) {
    for (const ticket of expired) outcome.set(ticket, { status: "failed", error: { code: "job_expired" } })
    setPending(listed, left)
    const what = expired.length === 1 ? "One signing link" : `${expired.length} signing links`
    formError(`${what} expired. You can still sign the rest.`)
  }
  // The backend says the jobs left are valid, whatever this computer's clock says: ask again later.
  if (!(deadline > Date.now())) deadline = Date.now() + EXPIRY_RECHECK
}

async function pollStatus() {
  if (signing) return
  checkExpiry()
  let status
  try {
    status = await api("/api/status")
  } catch (error) {
    // Whatever stops the agent from answering, signing would fail and say so: the PIN is not held back for it.
    if (++unanswered >= 3)
      setCard(
        "unknown",
        error.code === "agent_unreachable"
          ? { state: "problem", title: "PoliNetwork eSign stopped answering", detail: "Start it again." }
          : { state: "unknown", title: "Place your CIE on the reader", detail: "" },
      )
    return
  }
  unanswered = 0
  if (status.busy) return
  setRemembered(status.remembered)
  // A card moving on the reader can drop out of one answer: only a second one in a row means that it was taken away.
  if (status.card === "absent" && card === "present" && ++missing < REMOVED_AFTER) return
  setCard(status.card, cardView(status))
}

/**
 * Asks the agent about the card at once, and believes an answer without the card the first time: the signer is about
 * to send the PIN, or the agent just said that the card is not there. Returns whether the PIN may go.
 */
async function checkCard() {
  try {
    const status = await api("/api/status")
    if (!status.busy) {
      setRemembered(status.remembered)
      setCard(status.card, cardView(status))
    }
  } catch {
    // The polls go on, and decide after a few failures.
  }
  return cardReady()
}

/** What the card block says for a status: its state ("step" is the signer's next move), title and detail. */
function cardView(status) {
  const { reader, software } = describeStatus(status)
  const where = reader?.name || ""
  if (status.card === "present") return { state: "ready", title: "CIE detected", detail: where || software.name }
  if (status.card === "unknown") return { state: "unknown", title: "Place your CIE on the reader", detail: where }
  // Unavailable software lists no readers, so it comes first.
  if (!software.ok)
    return { state: "problem", title: "CIE ID is not set up", detail: "See the setup guide in the dashboard." }
  if (!reader?.ok) return { state: "step", title: "Connect the NFC card reader", detail: "Then place your CIE on it." }
  return { state: "step", title: "Place your CIE on the reader", detail: where }
}

/**
 * Shows what the agent says about the card, and holds the PIN and Sign back while no card is there: the typed digits
 * stay in the disabled field. When the card arrives, the focus moves on, unless the signer put it somewhere.
 */
function setCard(next, view) {
  missing = 0
  const was = cardReady()
  card = next
  $("card").dataset.state = view.state
  setText($("card-title"), view.title)
  const detail = $("card-detail")
  setText(detail, view.detail)
  detail.hidden = !view.detail
  // A long reader name is cut to one line: the full name shows on hover.
  detail.title = detail.scrollWidth > detail.clientWidth ? view.detail : ""
  const ready = cardReady()
  $("pin-fields").disabled = !ready
  $("submit").disabled = !ready
  if (card === "present" && CARD_MISSING.has(errorCode)) formError("")
  if (ready && !was && !$("form").hidden && document.activeElement === document.body) focusNext()
}

/** Errors of a signature that the card was not there for. */
const CARD_MISSING = new Set(["no_card", "no_reader"])
/** Errors of a signature that stopped before the PIN reached a card: the field keeps it for the next try. */
const PIN_KEPT = new Set([...CARD_MISSING, "busy"])
/** The code of the error shown above the buttons, "" for none or for one without a code. */
let errorCode = ""

function formError(message, code = "") {
  errorCode = message ? code : ""
  $("error").textContent = message
  $("error").hidden = !message
}

const PIN_HINT = $("pin-hint").textContent
/** Errors about the PIN itself, shown under its field. */
const PIN_ERRORS = new Set(["pin_incorrect", "pin_invalid", "pin_required"])

/** Shows message under the PIN field, in place of its hint; "" puts the hint back. */
function pinError(message) {
  setText($("pin-hint"), message || PIN_HINT)
  $("pin-hint").classList.toggle("bad", Boolean(message))
  if (message) $("pin").setAttribute("aria-invalid", "true")
  else $("pin").removeAttribute("aria-invalid")
}

/** What to say under the field after a wrong PIN. The count of this computer can miss wrong PINs typed elsewhere. */
function wrongPIN() {
  if (lastAttempt()) return "Wrong PIN."
  if (attempts?.card) return `Wrong PIN. ${attempts.left} attempts left.`
  return "Wrong PIN. Three wrong PINs in a row block your CIE."
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
  const failed = docs.map((d) => outcome.get(d.ticket)?.error?.code).find(Boolean)
  // The dashboard checks the version again before each signature.
  if (!signed && docs.some((d) => outcome.get(d.ticket)?.error?.code === "agent_outdated")) return outdated()

  if (docs.length === 1 && !all) {
    const result = outcome.get(docs[0].ticket)
    // One document: an error that retrying can fix goes back to the PIN, anything else ends here.
    if (!again.length) return fatalError(result.error)
    notify("error", failed)
    return showForm(docs, [docs[0].ticket], result.error.message)
  }
  notify(all ? "completed" : "error", all ? undefined : failed)

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
  if (signing || !cardReady()) return
  // Without a PIN the agent uses the one it remembers for this browser.
  const body = { tickets: pending, origin }
  const pin = remembered ? "" : $("pin").value.trim()
  if (!remembered) {
    if (!/^\d{8}$/.test(pin)) {
      pinError(
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
  signing = true
  // The last status had no card, which may only have moved on the reader: ask again rather than send the PIN for
  // nothing. When the card is gone, the form goes back to waiting for it, with the PIN still typed.
  if (missing > 0 && !(await checkCard())) {
    signing = false
    return
  }
  // Cleared before the form goes away, so a browser watching the submission has nothing to offer to save.
  $("pin").value = ""
  formError("")
  pinError("")
  $("working-title").textContent = pending.length === 1 ? "Signing…" : `Signing ${pending.length} documents…`
  show("working")
  let result
  try {
    result = await api("/api/sign", body)
  } catch (error) {
    signing = false
    if (JOB_ENDED.has(error.code) || TERMINAL.has(error.code)) return fatalError(error)
    // After a failure the agent no longer remembers the PIN, unless the card was busy and was never tried.
    if (error.code !== "busy") remembered = null
    if (error.code === "pin_incorrect") attempts = error.attempts || attempts
    show("form")
    showPIN()
    if (PIN_KEPT.has(error.code)) $("pin").value = pin
    // The card block says it when it holds the PIN back for the card.
    const shown = CARD_MISSING.has(error.code) && !(await checkCard())
    if (error.code === "pin_incorrect") pinError(wrongPIN())
    else if (PIN_ERRORS.has(error.code)) pinError(error.message)
    else if (!shown) formError(error.message || "The signature failed.", error.code)
    // Asking for the PIN is not a failure of the signature.
    if (error.code !== "pin_required") notify("error", error.code)
    return
  }
  signing = false
  if (result.signer?.displayName) signer = result.signer.displayName
  // Absent when no document was left to sign, so the PIN was not used.
  if (result.attempts !== undefined) attempts = result.attempts
  for (const r of result.results || []) outcome.set(r.ticket, r)
  showResults()
})

/** Shows the PIN's digits so that the signer can check them, or masks them again. */
function showDigits(shown) {
  $("pin-show").setAttribute("aria-pressed", String(shown))
  if (masking) $("pin").classList.toggle("masked", !shown)
  else $("pin").type = shown ? "text" : "password"
}

// A click on the eye leaves the focus in the field, to go on typing.
$("pin-show").addEventListener("mousedown", (event) => event.preventDefault())
$("pin-show").addEventListener("click", () => showDigits($("pin-show").getAttribute("aria-pressed") !== "true"))

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
