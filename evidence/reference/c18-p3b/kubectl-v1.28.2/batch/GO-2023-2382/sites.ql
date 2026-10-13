import go
from DataFlow::Node n
where
  (
    exists(Method m | m.hasQualifiedName("net/http/internal", "chunkedReader", "Read") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/net/http/internal/%")
select n, "sink site"
