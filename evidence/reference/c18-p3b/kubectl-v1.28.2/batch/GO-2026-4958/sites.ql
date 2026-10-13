import go
from DataFlow::Node n
where
  (
    exists(Method m | m.hasQualifiedName("github.com/moby/spdystream/spdy", "Framer", "ReadFrame") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("github.com/moby/spdystream/spdy", "NewFramer") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("github.com/moby/spdystream", "Connection", "Serve") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("github.com/moby/spdystream", "NewConnection") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/github.com/moby/spdystream/spdy/%") and not n.getFile().getAbsolutePath().matches("%/github.com/moby/spdystream/%")
select n, "sink site"
