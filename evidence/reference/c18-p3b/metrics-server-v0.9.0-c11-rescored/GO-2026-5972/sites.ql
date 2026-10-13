import go
from DataFlow::Node n
where
  (
    exists(Function m | m.hasQualifiedName("encoding/asn1", "Unmarshal") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/encoding/asn1/%")
select n, "sink site"
