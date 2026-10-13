import go
from DataFlow::Node n
where
  (
    exists(Method m | m.hasQualifiedName("crypto/internal/nistec", "P256Point", "ScalarBaseMult") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("crypto/internal/nistec", "P256Point", "ScalarMult") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("crypto/internal/nistec", "P256Point", "SetBytes") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/crypto/internal/nistec/%")
select n, "sink site"
