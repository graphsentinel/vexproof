import go
from DataFlow::Node n
where
  (
    exists(Method m | m.hasQualifiedName("os", "File", "ReadDir") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("os", "File", "Readdir") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("os", "ReadDir") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/os/%")
select n, "sink site"
