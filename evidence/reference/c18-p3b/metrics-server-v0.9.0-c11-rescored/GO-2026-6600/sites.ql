import go
from DataFlow::Node n
where
  (
    exists(Method m | m.hasQualifiedName("html/template", "Template", "Execute") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("html/template", "Template", "ExecuteTemplate") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/html/template/%")
select n, "sink site"
