// DOM XSS: tainted/local value assigned to innerHTML without sanitization.
function render(el, localValue) {
  el.innerHTML = localValue;
}
