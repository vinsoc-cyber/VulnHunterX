/**
 * @name WebSocket connection over unencrypted ws://
 * @description `new WebSocket('ws://...')` (or a tainted URL not validated
 *              to start with `wss://`) transmits frames in cleartext,
 *              allowing network attackers to read or modify messages.
 *              Use `wss://` for any session-bearing or sensitive channel.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision medium
 * @id js/insecure-websocket
 * @tags external/cwe/cwe-319
 *       security
 */

import javascript

from NewExpr ne, Expr urlArg, string url
where
  ne.getCalleeName() = "WebSocket" and
  urlArg = ne.getArgument(0) and
  (
    url = urlArg.getStringValue() and url.matches("ws://%")
    or
    // Template literal whose head starts with ws://
    exists(TemplateLiteral t |
      t = urlArg and t.getElement(0).(TemplateElement).getRawValue().matches("ws://%") and
      url = "<template ws://...>"
    )
  )
select ne,
  "WebSocket connection to '" + url + "' is unencrypted. " +
  "Use wss:// for any channel that carries authentication or sensitive data."
