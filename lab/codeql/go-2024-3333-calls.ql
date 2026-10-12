/**
 * @name Calls to the GO-2024-3333 (CVE-2024-45338) symbols of golang.org/x/net/html
 * @description Negative control: the maintainers' "not affected" decision (k/k #129347) predicts no call sites.
 * @kind problem
 * @problem.severity recommendation
 * @id vexproof/go-2024-3333-calls
 */

import go

from DataFlow::CallNode c, Function f
where
  f.hasQualifiedName("golang.org/x/net/html",
    ["Parse", "ParseFragment", "ParseWithOptions", "ParseFragmentWithOptions"]) and
  c = f.getACall() and
  // calls inside the vulnerable package itself (Parse -> ParseWithOptions wrappers) are not callers of the package
  not c.getFile().getAbsolutePath().matches("%/golang.org/x/net/html/%")
select c, "Call to " + f.getName() + " (GO-2024-3333 symbol)."
