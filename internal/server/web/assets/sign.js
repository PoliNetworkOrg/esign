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
const sections = ["loading", "fatal", "form", "working", "done"]
let pollTimer = 0
let signing = false
/** Every document of the link, in order: { ticket, job } or { ticket, error }. */
let docs = []
/** Tickets the PIN form signs. */
let pending = []
/** What happened to each ticket: { status, error }. */
const outcome = new Map()
let signer = ""

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
  const res = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: { "X-PN-eSign": "1", ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw Object.assign(new Error(data.error?.message || res.statusText), data.error || {})
  return data
}

function fatal(message) {
  stopPolling()
  $("fatal-message").textContent = message
  show("fatal")
}

const JOB_ENDED = new Set([
  "ticket_invalid",
  "too_many_tickets",
  "job_expired",
  "job_done",
  "job_cancelled",
  "origin_forbidden",
  "signer_mismatch",
])
/** Card errors after which the same documents can be signed again. */
const RETRYABLE = new Set(["card_removed", "device_error", "no_card", "no_reader"])

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
    line(li, doc.error.message, "bad")
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
  else line(text, result.error?.message || "Not signed", "bad")
  li.classList.add("result")
  li.append(mark, text)
}

async function load() {
  if (!tickets.length || !origin) return fatal("This page needs a signing link from the dashboard.")
  if (tickets.length > MAX_TICKETS) return fatal(`Sign at most ${MAX_TICKETS} documents at a time.`)
  if (tickets.length > 1) $("loading-text").textContent = "Loading the documents…"
  try {
    ;({ jobs: docs } = await api("/api/job", { tickets, origin }))
  } catch (error) {
    return fatal(error.message || "Cannot load the document.")
  }
  for (const doc of docs) if (!doc.job) outcome.set(doc.ticket, { status: "failed", error: doc.error })
  const ready = docs.filter((d) => d.job)
  if (!ready.length) {
    if (docs.length === 1) return fatal(docs[0].error.message)
    fillList($("fatal-docs"), docs, describeDoc)
    return fatal("None of these documents can be signed.")
  }
  showForm(docs, ready.map((d) => d.ticket))
}

/** Shows the PIN form for the tickets to sign, listing the given documents. */
function showForm(listed, toSign, message = "") {
  pending = toSign
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
  formError(message)
  show("form")
  $("pin").focus()
  startPolling()
}

function startPolling() {
  stopPolling()
  pollStatus()
  pollTimer = setInterval(pollStatus, 1500)
}

function stopPolling() {
  clearInterval(pollTimer)
}

async function pollStatus() {
  if (signing) return
  let status
  try {
    status = await api("/api/status")
  } catch {
    return
  }
  if (status.busy) return
  const card = $("card")
  const usable = status.providers.filter((p) => p.available)
  const readers = [...new Set(usable.flatMap((p) => p.readers || []))]
  if (status.ready) {
    card.dataset.state = "ready"
    $("card-text").textContent = readers.length ? `Card detected on ${readers[0]}` : "Card detected"
  } else if (usable.length && readers.length) {
    card.dataset.state = "waiting"
    $("card-text").textContent = `Place your CIE on the reader (${readers[0]})`
  } else if (usable.length) {
    card.dataset.state = "waiting"
    $("card-text").textContent = "Connect the NFC card reader"
  } else {
    card.dataset.state = "waiting"
    $("card-text").textContent = "No CIE software found. See the setup guide in the dashboard."
  }
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
      // One document: a card error goes back to the PIN, anything else ends here, as before.
      if (again.length) return showForm(docs, [docs[0].ticket], result.error.message)
      return fatal(result.error?.message || "The signature failed.")
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
  else if (again.length) message += " Keep the CIE still on the reader and try again."
  else message += " Start again from the dashboard for the others."
  $("done-message").textContent = message.trim()
  $("retry").hidden = again.length === 0
  show("done")
  $("done-title").focus()
  if (all) setTimeout(() => window.close(), 4000)
}

$("form").addEventListener("submit", async (event) => {
  event.preventDefault()
  const pin = $("pin").value.trim()
  if (!/^\d{8}$/.test(pin)) {
    formError("Type the 8 digits of your CIE PIN.")
    $("pin").focus()
    return
  }
  formError("")
  signing = true
  $("working-title").textContent = pending.length === 1 ? "Signing…" : `Signing ${pending.length} documents…`
  show("working")
  let result
  try {
    result = await api("/api/sign", { tickets: pending, origin, pin })
  } catch (error) {
    signing = false
    if (JOB_ENDED.has(error.code)) return fatal(error.message)
    show("form")
    $("pin").value = ""
    let message = error.message || "The signature failed."
    if (error.code === "pin_incorrect") {
      message =
        typeof error.retriesLeft === "number"
          ? `Wrong PIN. ${error.retriesLeft} ${error.retriesLeft === 1 ? "attempt" : "attempts"} left before the PIN is blocked.`
          : "Wrong PIN. After 3 wrong attempts the PIN is blocked and needs the PUK."
    }
    formError(message)
    $("pin").focus()
    notify("error", error.code)
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

load()
