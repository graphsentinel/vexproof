import go
from DataFlow::Node n
where
  (
    exists(Method m | m.hasQualifiedName("golang.org/x/net/html", "Tokenizer", "Next") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/golang.org/x/net/html/%")
select n, "sink site"
