import go
from DataFlow::Node n
where
  (
    exists(Function m | m.hasQualifiedName("archive/zip", "NewReader") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/archive/zip/%")
select n, "sink site"
