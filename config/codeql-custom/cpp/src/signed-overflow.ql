/**
 * @name Left-shift of signed integer
 * @description Left-shifting a signed integer whose result does not fit
 *              in its destination type is undefined behaviour in C and
 *              C++11 (5.8p2). Shifts into the sign bit of an `int` or
 *              `long` create UB even on twos-complement platforms.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.5
 * @precision medium
 * @id cpp/signed-overflow
 * @tags external/cwe/cwe-190
 *       security
 */

import cpp

/** A `<<` whose left operand is signed. */
class SignedLeftShift extends LShiftExpr {
  SignedLeftShift() {
    this.getLeftOperand().getType().getUnspecifiedType().(IntegralType).isSigned() and
    // Skip when the LHS is a literal small constant (e.g. `1 << n` flag pattern)
    // where the result still fits when n is small. We conservatively flag
    // shifts whose LHS is NOT a small literal.
    not (
      this.getLeftOperand().getValue().toInt() in [0 .. 1] and
      this.getRightOperand().getValue().toInt() in [0 .. 30]
    )
  }
}

from SignedLeftShift shl
select shl,
  "Left-shift of a signed value can shift into the sign bit (UB per " +
  "C11 6.5.7 / C++11 5.8). Cast the LHS to its unsigned counterpart " +
  "before shifting."
