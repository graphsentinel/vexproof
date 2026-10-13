import go
from DataFlow::Node n
where
  (
    exists(Method m | m.hasQualifiedName("net/textproto", "Reader", "ReadMIMEHeader") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/net/textproto/%")
select n, "sink site"
