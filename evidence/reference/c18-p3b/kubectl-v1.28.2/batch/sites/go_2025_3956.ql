import go
from DataFlow::Node n
where
  (
    exists(Function m | m.hasQualifiedName("os/exec", "LookPath") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/os/exec/%")
select n, "sink site"
