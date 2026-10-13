import go
from DataFlow::Node n
where
  (
    exists(Method m | m.hasQualifiedName("archive/tar", "Reader", "Next") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/archive/tar/%")
select n, "sink site"
