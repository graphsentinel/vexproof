import go
from DataFlow::Node n
where
  (
    exists(Method m | m.hasQualifiedName("net/http", "Server", "Serve") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/net/http/%")
select n, "sink site"
