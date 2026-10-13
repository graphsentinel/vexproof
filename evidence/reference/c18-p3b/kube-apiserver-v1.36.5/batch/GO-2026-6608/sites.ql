import go
from DataFlow::Node n
where
  (
    exists(Method m | m.hasQualifiedName("net/textproto", "Reader", "ReadMIMEHeader") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("mime/multipart", "Reader", "ReadForm") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/net/textproto/%") and not n.getFile().getAbsolutePath().matches("%/mime/multipart/%")
select n, "sink site"
