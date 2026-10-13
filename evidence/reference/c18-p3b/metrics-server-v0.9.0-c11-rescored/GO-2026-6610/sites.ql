import go
from DataFlow::Node n
where
  (
    exists(Method m | m.hasQualifiedName("golang.org/x/net/http2", "Transport", "NewClientConn") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("golang.org/x/net/http2", "Transport", "RoundTrip") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("golang.org/x/net/http2", "noDialH2RoundTripper", "NewClientConn") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("golang.org/x/net/http2", "noDialH2RoundTripper", "RoundTrip") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("golang.org/x/net/http2", "unencryptedTransport", "RoundTrip") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("net/http", "Client", "Do") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/golang.org/x/net/http2/%") and not n.getFile().getAbsolutePath().matches("%/net/http/%")
select n, "sink site"
