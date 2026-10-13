import go
from DataFlow::Node n
where
  (
    exists(Method m | m.hasQualifiedName("crypto/x509", "Certificate", "Verify") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("crypto/x509", "Certificate", "VerifyHostname") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/crypto/x509/%")
select n, "sink site"
