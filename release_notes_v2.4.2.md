# Flow 2.4.2 — AMOLED glass

## Interface

- Pure black AMOLED canvas by default, dark translucent frosted panels, subtle silver borders, readable silver typography, and a silver primary action. Existing saved appearance preferences are retained.
- Windows 11 22H2+ native frame effects when supported and permitted by existing OS preferences. The AMOLED canvas remains opaque black; panels use translucent materials. Other systems retain the same usable dark appearance without native effects; no system preferences are changed.
- Compact recipient bar, a dedicated device page, useful empty-state actions, shorter labels, and clearer text hierarchy in Arabic and English.
- Intrinsic content sizing, touch targets and keyboard navigation across desktop and mobile layouts.

## Usability

- Received files on Android use a separate browse/open/export mode that works without a connected recipient.
- Dedicated paste action for the other device's pairing code, and clear save feedback.
- Verification times out with actionable retry/repair guidance instead of remaining indefinitely in a verifying state. Outdated probe results cannot replace the current recipient's state.
- Text that was acknowledged clears only when the draft has not been edited since submission, including when link cleaning changes the sent text.
- Stable list models preserve controls and update only changed rows during progress/presence refreshes.

## Compatibility

Protocol 3 and the existing private pairing data are preserved. This UI update remains compatible with 2.4.1; no new pairing is required for already paired devices. Versions before 2.4.1 still need the protocol upgrade.

Android packages retain the existing release signing identity, embedded licenses, and 16 KB ELF alignment. Physical Android device validation remains separate from desktop mobile preview and build verification.
