"use strict"

// What an /api/status answer means for the user, shared by the signing page and the home page so they never disagree.

const SOFTWARE = {
  "cie-mw": "CIE ID",
  opencie: "OpenCIE",
  cie: "Built into PoliNetwork eSign",
  soft: "Development key (signatures not valid)",
}

/**
 * Describes the reader, the card and the software that would sign, each { ok, text }. The reader also has its name
 * ("" without one), and the software, when none is usable, every provider's detail for support. The development key
 * needs no reader, so with it reader and card are left out; card is left out without a reader too. ready is true when
 * everything described is ok.
 */
function describeStatus(status) {
  const available = status.providers.filter((p) => p.available)
  // The provider the agent opens first (Server.open): available, and not known to be without a card.
  const signing = available.find((p) => p.cardPresent !== false) || available[0]
  const software = signing
    ? { ok: true, text: SOFTWARE[signing.provider] || signing.provider }
    : {
        ok: false,
        text: "Signing software not available",
        detail: status.providers.map((p) => `${p.provider}: ${p.detail || "not available"}`).join("\n"),
      }
  if (signing?.provider === "soft") return { ready: status.ready, software }

  // Readers of usable providers first: they are the ones named.
  const [name = ""] = new Set([...available, ...status.providers].flatMap((p) => p.readers || []))
  const reader = name
    ? { ok: true, text: `Card reader: ${name}`, name }
    : { ok: false, text: "Connect the NFC card reader", name }
  const card = name
    ? { ok: status.ready, text: status.ready ? "CIE detected" : "Place your CIE on the reader" }
    : undefined
  return { ready: reader.ok && Boolean(card?.ok) && software.ok, reader, card, software }
}
