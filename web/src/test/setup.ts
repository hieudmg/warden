import "@testing-library/jest-dom/vitest"

// jsdom does not implement pointer-capture APIs that Radix primitives
// (notably Select) rely on; without these no-ops their pointer handlers
// throw during tests.
if (!Element.prototype.hasPointerCapture) {
  Element.prototype.hasPointerCapture = () => false
  Element.prototype.setPointerCapture = () => {}
  Element.prototype.releasePointerCapture = () => {}
}

// Radix Select scrolls the selected item into view while opening; jsdom
// leaves scrollIntoView unimplemented.
if (!Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = () => {}
}
