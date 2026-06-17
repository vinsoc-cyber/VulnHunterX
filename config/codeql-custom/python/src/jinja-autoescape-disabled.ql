/**
 * @name Jinja2 template autoescaping disabled
 * @description A Jinja2 environment or framework template setup is configured
 *              with `autoescape=False`. With autoescaping off, every value
 *              rendered in a template (`{{ value }}`) is emitted unescaped, so
 *              any user-controlled value reaching a template is a stored or
 *              reflected XSS sink. This is framework-general: it covers
 *              `jinja2.Environment(autoescape=False)`, aiohttp-jinja2's
 *              `setup(..., autoescape=False)` / `setup_jinja(...)`, and similar
 *              template-setup helpers — a class the built-in suites miss.
 * @kind problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id py/jinja-autoescape-disabled
 * @tags external/cwe/cwe-79
 *       security
 */

import python

/** The boolean literal `False`. */
predicate isFalseLiteral(Expr e) {
  e.(NameConstant).getId() = "False"
  or
  // Older/alternative AST shapes represent the literal as a plain name.
  e.(Name).getId() = "False"
}

/**
 * A call that constructs a Jinja2 environment or wires Jinja2 into a web
 * framework. Matched by the called name so import aliases (e.g.
 * `from aiohttp_jinja2 import setup as setup_jinja`) are covered.
 */
predicate isJinjaSetupCall(Call c) {
  exists(string name |
    (
      c.getFunc().(Name).getId() = name or
      c.getFunc().(Attribute).getName() = name
    ) and
    name in [
        "Environment", "setup", "setup_jinja", "setup_jinja2",
        "render_template", "Template"
      ]
  )
}

from Call c, Keyword k
where
  isJinjaSetupCall(c) and
  k = c.getANamedArg() and
  k.getArg() = "autoescape" and
  isFalseLiteral(k.getValue())
select k,
  "Jinja2 autoescaping is disabled (autoescape=False); user-controlled values " +
  "rendered in templates are unescaped, enabling XSS. Enable autoescape " +
  "(autoescape=True / select_autoescape([...]))."
