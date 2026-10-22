"use strict"

// The home page shows whether this computer is ready to sign. It polls only while visible: a status call holds the
// card, and a signature arriving meanwhile waits for it.

const $ = (id) => document.getElementById(id)
let timer = 0
let inFlight = false

/** Sets text only when it changes, so the live region announces changes and nothing else. */
function setText(el, text) {
  if (el.textContent !== text) el.textContent = text
}

function setRow(id, row) {
  const el = $(id)
  el.hidden = !row
  if (!row) return
  el.dataset.state = row.ok ? "ready" : "waiting"
  setText(el.querySelector(".status-text"), row.text)
}

function setHeading(text, ready) {
  setText($("heading"), text)
  $("ready-icon").hidden = !ready
}

function render(status) {
  const { ready, reader, card, software } = describeStatus(status)
  setRow("reader", reader)
  setRow("card", card)
  setRow("software", software)
  setText($("software-detail"), software.detail || "")
  $("software-detail").hidden = !software.detail
  setHeading(ready ? "Ready to sign" : "PoliNetwork eSign is running", ready)
  setText($("version"), `PoliNetwork eSign ${status.version}`)
}

/** Shows heading and text in place of the status rows. */
function renderProblem(heading, text) {
  setRow("reader", { ok: false, text })
  setRow("card", undefined)
  setRow("software", undefined)
  $("software-detail").hidden = true
  setHeading(heading, false)
}

async function poll() {
  clearTimeout(timer)
  inFlight = true
  try {
    const res = await fetch("/api/status", { headers: { "X-PN-eSign": "1" }, cache: "no-store" })
    const status = await res.json().catch(() => ({}))
    // While a signature runs the agent answers busy: the last state still holds. A failed check holds nothing.
    if (!res.ok) renderProblem("PoliNetwork eSign is running", status.error?.message || "Cannot check the card reader.")
    else if (!status.busy) render(status)
  } catch {
    renderProblem("PoliNetwork eSign stopped", "Open it again.")
  }
  inFlight = false
  if (document.visibilityState === "visible") timer = setTimeout(poll, 1500)
}

document.addEventListener("visibilitychange", () => {
  clearTimeout(timer)
  if (document.visibilityState === "visible" && !inFlight) poll()
})

if (document.visibilityState === "visible") poll()
