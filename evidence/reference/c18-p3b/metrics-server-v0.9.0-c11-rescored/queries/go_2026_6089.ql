/**
 * @name sinkgen GO-2026-6089: untrusted data reaches the vulnerable symbol's input
 * @kind path-problem
 * @problem.severity warning
 * @id vexreach/sinkgen-go-2026-6089
 */

import go

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    // template v3: a *http.Request read inside an HTTP client's round trip is the program's own outgoing request,
    // not remote input (batch run on metrics-server: 3 of 4 paths came from there)
    // heuristic, by function name and by HTTP client implementation file
    n instanceof RemoteFlowSource and
    not n.getRoot().(FuncDef).getName().regexpMatch("(?i).*(roundtrip|dial).*") and
    not n.getFile().getAbsolutePath()
        .regexpMatch(".*/(x/net/http2/transport[^/]*|net/http/(transport|client)[^/]*|grpc/internal/transport/http2_client)[.]go")
    or
    exists(Field f | f.hasQualifiedName("net/http", "Response", "Body") | n = f.getARead())
  }

  predicate isSink(DataFlow::Node n) {
    exists(Method m | m.hasQualifiedName("net/http", "Server", "Serve") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode src, Flow::PathNode sink
where Flow::flowPath(src, sink)
select sink.getNode(), src, sink, "untrusted data reaches a GO-2026-6089 sink", src.getNode(), "source"
