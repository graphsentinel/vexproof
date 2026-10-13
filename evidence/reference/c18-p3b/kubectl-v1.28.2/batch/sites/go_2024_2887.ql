import go
from DataFlow::Node n
where
  (
    exists(Method m | m.hasQualifiedName("net/netip", "Addr", "IsLoopback") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("net/netip", "Addr", "IsMulticast") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/net/netip/%")
select n, "sink site"
