# js/sql-injection @ app/data/user-dao.js:104

**Verdict:** TP · **Confidence:** Medium (0.78) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The flagged sink is present at line 104, and the visible code directly uses externally sourced `userName` in a MongoDB query selector on line 105. No visible validation, type coercion, or MongoDB-operator sanitization exists in the provided function or additional context, making this an exploitable NoSQL injection path if attacker-controlled objects reach the sink as reported.

## Data flow

external req.body (reported line 198) → object construction (reported line 191) → userName (reported line 193) → userName (reported lines 206/208) → getUserByUserName parameter userName (app/data/user-dao.js:103) → query value userName: userName (app/data/user-dao.js:105) → MongoDB usersCol.findOne query object sink (app/data/user-dao.js:104). Additional context: no recorded callers for getUserByUserName and no handler body found, so no extra sanitizer or guard is visible.

## Answers

1. Step 0 / flagged line: The flagged line is present at `app/data/user-dao.js:104` and its exact text is `usersCol.findOne({`. It lives in `this.getUserByUserName = (userName, callback) => { ... }`, defined at lines 103-107. The rule-relevant construct is present: a MongoDB query object is passed to `findOne`, with `userName` used as the query value on line 105.
2. Step 1: The potentially dangerous data originates from remote/external user input, specifically `req.body` at reported line 198 in the CodeQL dataflow. The new context did not reveal the handler body, but the supplied scanner note states this is an external attacker-controllable source.
3. Step 2: The traced flow remains: `req.body` at reported line 198 → object construction at reported line 191 → `userName` at reported line 193 → `userName` at reported lines 206 and/or 208 → parameter `userName` in `getUserByUserName` at visible line 103 → query field value `userName: userName` at line 105 → query object sink beginning at flagged line 104. Additional context says no recorded callers were found for `getUserByUserName`, and the handler for lines 191-208 was not found, so no additional transformation details are visible.
4. Step 3: No validation, sanitization, encoding, type coercion, or MongoDB operator stripping is visible on the path. In the visible function, `userName` is accepted at line 103 and directly inserted into the MongoDB query object at line 105. The additional context did not provide any upstream sanitizer or guard.
5. Step 4: The sink is the MongoDB `findOne` call beginning at line 104, using the query selector `{ userName: userName }` on lines 104-106. The dangerous operation is building a MongoDB query selector from attacker-controlled data; if `userName` can be an object, MongoDB can interpret operator keys such as `$ne` or `$gt` rather than performing a simple string equality comparison.
6. Step 5: No automatic framework or library protection is visible. The code uses the MongoDB collection API directly via `usersCol.findOne` at line 104. The additional context did not show an ODM schema, middleware, request validator, or configuration that would coerce `userName` to a string or reject operator objects.
7. Step 6: The exact authentication state is still not visible. However, the scanner-provided source is external `req.body`, and the instructions state that the scanner has established external reachability. The new context saying no recorded callers were found does not provide a visible authentication guard or negate the reported external dataflow.
8. Step 7: The concrete impact is NoSQL/MongoDB query injection. An attacker controlling `userName` may be able to alter the selector used by `findOne`, potentially causing unintended user records to be returned. Depending on the caller’s use of the returned document, this can support data exposure, authentication bypass, or privilege escalation.
9. Step 8: The weakest link is the lack of visible type validation or MongoDB query sanitization before line 105. The code directly places externally controlled data into the query selector, and the additional context did not reveal any complete defense.
