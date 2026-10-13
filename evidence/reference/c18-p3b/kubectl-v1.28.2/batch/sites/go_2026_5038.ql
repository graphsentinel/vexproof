import go
from DataFlow::Node n
where
  (
    exists(Method m | m.hasQualifiedName("mime", "WordDecoder", "DecodeHeader") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/mime/%")
select n, "sink site"
