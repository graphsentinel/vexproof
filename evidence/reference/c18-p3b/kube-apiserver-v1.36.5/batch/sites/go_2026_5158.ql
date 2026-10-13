import go
from DataFlow::Node n
where
  (
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/baggage", "New") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/baggage", "Parse") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/propagation", "Baggage", "Extract") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/baggage/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/propagation/%")
select n, "sink site"
