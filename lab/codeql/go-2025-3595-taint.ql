/**
 * @name Upstream HTTP response body reaches the vulnerable x/net/html tokenizer (GO-2025-3595)
 * @description Sink derived from the OSV symbol golang.org/x/net/html.(*Tokenizer).Next: the reader passed to the
 *              tokenizer's constructors. Source: the body of an HTTP response the program received (whoever runs
 *              the upstream service controls it).
 * @kind path-problem
 * @problem.severity warning
 * @id vexproof/go-2025-3595-taint
 */

import go

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    exists(Field f | f.hasQualifiedName("net/http", "Response", "Body") | n = f.getARead())
  }

  predicate isSink(DataFlow::Node n) {
    exists(Function f |
      f.hasQualifiedName("golang.org/x/net/html", ["NewTokenizer", "NewTokenizerFragment"])
    |
      n = f.getACall().getArgument(0)
    )
  }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode src, Flow::PathNode sink
where Flow::flowPath(src, sink)
select sink.getNode(), src, sink,
  "HTTP response body from $@ reaches html.NewTokenizer, whose (*Tokenizer).Next is the GO-2025-3595 symbol.",
  src.getNode(), "this read"
