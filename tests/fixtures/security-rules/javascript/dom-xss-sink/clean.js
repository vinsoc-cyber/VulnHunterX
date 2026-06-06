// Safe: textContent, empty clear, and DOMPurify-sanitized assignment.
function render(el, localValue) {
  el.textContent = localValue;
  el.innerHTML = "";
  el.innerHTML = DOMPurify.sanitize(localValue);
}
