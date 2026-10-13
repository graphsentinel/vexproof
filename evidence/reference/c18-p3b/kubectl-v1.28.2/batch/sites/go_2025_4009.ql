import go
from DataFlow::Node n
where
  (
    exists(Function m | m.hasQualifiedName("encoding/pem", "Decode") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/encoding/pem/%")
select n, "sink site"
