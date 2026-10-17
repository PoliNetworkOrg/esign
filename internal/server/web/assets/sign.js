"use strict"

// The dashboard opens /sign?ticket=…&origin=… in a popup. The ticket is moved to sessionStorage and removed from the
// address bar, so it does not stay in the history.
const params = new URLSearchParams(location.search)
if (params.has("ticket")) {
  sessionStorage.setItem("ticket", params.get("ticket") || "")
  sessionStorage.setItem("origin", params.get("origin") || "")
  history.replaceState(null, "", "/sign")
}
const ticket = sessionStorage.getItem("ticket") || ""
const origin = sessionStorage.getItem("origin") || ""

const $ = (id) => document.getElementById(id)
const sections = ["loading", "fatal", "form", "working", "done"]
let pollTimer = 0
let signing = false

function show(id) {
  for (const s of sections) $(s).hidden = s !== id
}

/** Tells the dashboard what happened; the dashboard also polls its backend, so this is only a shortcut. */
function notify(status, detail) {
  try {
    if (window.opener && origin) window.opener.postMessage({ type: "pn-sign-agent", status, detail }, origin)
  } catch {
    // The opener navigated away or is cross-origin isolated: polling covers it.
  }
}

async function api(path, body) {
  const res = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: { "X-PN-Sign-Agent": "1", ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw Object.assign(new Error(data.error?.message || res.statusText), data.error || {})
  return data
}

function fatal(message) {
  clearInterval(pollTimer)
  $("fatal-message").textContent = message
  show("fatal")
}

const JOB_ENDED = new Set(["ticket_invalid", "job_expired", "job_done", "job_cancelled", "origin_forbidden", "signer_mismatch"])

async function load() {
  if (!ticket || !origin) return fatal("This page needs a signing link from the dashboard.")
  let job
  try {
    ;({ job } = await api("/api/job", { ticket, origin }))
  } catch (error) {
    return fatal(error.message || "Cannot load the document.")
  }
  $("doc-title").textContent = job.document.title
  $("doc-file").textContent = job.document.fileName
  $("doc-place").textContent = `Page ${job.placement.page + 1} of ${job.document.pages}`
  $("doc-signer").textContent = job.signer.role ? `${job.signer.name} · ${job.signer.role}` : job.signer.name
  document.title = `Sign “${job.document.title}” · PoliNetwork`
  show("form")
  $("pin").focus()
  pollStatus()
  pollTimer = setInterval(pollStatus, 1500)
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
  show("working")
  try {
    const result = await api("/api/sign", { ticket, origin, pin })
    clearInterval(pollTimer)
    const remaining = result.request?.remaining ?? 0
    $("done-message").textContent =
      remaining > 0
        ? `Signed as ${result.signer.displayName}. ${remaining} more ${remaining === 1 ? "signature is" : "signatures are"} needed.`
        : `Signed as ${result.signer.displayName}. You can close this window.`
    show("done")
    notify("completed")
    setTimeout(() => window.close(), 4000)
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
  }
})

$("pin").addEventListener("input", () => {
  $("pin").value = $("pin").value.replace(/\D/g, "").slice(0, 8)
})

$("cancel").addEventListener("click", async () => {
  try {
    await api("/api/cancel", { ticket, origin })
  } catch {
    // Closing anyway: the job expires on its own.
  }
  notify("cancelled")
  window.close()
})

for (const button of document.querySelectorAll("[data-close]")) button.addEventListener("click", () => window.close())

load()
