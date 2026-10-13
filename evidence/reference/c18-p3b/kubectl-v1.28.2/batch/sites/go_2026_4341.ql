import go
from DataFlow::Node n
where
  (
    exists(Function m | m.hasQualifiedName("net/url", "ParseQuery") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("net/url", "URL", "Query") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/net/url/%")
select n, "sink site"
