import go
from DataFlow::Node n
where
  (
    exists(Function m | m.hasQualifiedName("google.golang.org/grpc/internal/transport", "NewHTTP2Client") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("google.golang.org/grpc/internal/transport", "http2Client", "Close") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("google.golang.org/grpc/internal/transport", "http2Client", "GracefulClose") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/google.golang.org/grpc/internal/transport/%")
select n, "sink site"
