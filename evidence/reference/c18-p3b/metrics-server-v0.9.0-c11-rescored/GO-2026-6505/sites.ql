import go
from DataFlow::Node n
where
  (
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "TracerProvider", "Tracer") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "init$1") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "logDropped$1") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "nonRecordingSpan", "AddEvent") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "nonRecordingSpan", "End") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "nonRecordingSpan", "IsRecording") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "nonRecordingSpan", "SetAttributes") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "nonRecordingSpan", "SetName") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "nonRecordingSpan", "SetStatus") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "nonRecordingSpan", "SpanContext") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "nonRecordingSpan", "TracerProvider") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "recordingSpan", "AddEvent") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "recordingSpan", "End") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "recordingSpan", "IsRecording") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "recordingSpan", "SetAttributes") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "recordingSpan", "SetName") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "recordingSpan", "SetStatus") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "recordingSpan", "SpanContext") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "recordingSpan", "TracerProvider") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "tracer", "Start") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/observ", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/observ", "init$1") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/observ", "init$2") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/observ", "init$3") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/observ", "init$4") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/internal/tracetransform", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/retry", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk", "Version") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/observ", "NewTracer") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/observ", "Tracer", "Enabled") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/observ", "Tracer", "SpanEnded") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/observ", "Tracer", "SpanLive") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/observ", "Tracer", "SpanStarted") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/observ", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/observ", "init$1") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/envconfig", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/resource", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/instrumentation", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/x", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/internal/x", "Feature[string]", "Enabled") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/internal/x", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/otlpconfig", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/counter", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/env", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/sdk/trace/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/observ/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/internal/tracetransform/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/retry/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/sdk/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/sdk/trace/internal/observ/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/envconfig/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/sdk/resource/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/sdk/instrumentation/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/x/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/sdk/internal/x/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/otlpconfig/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/counter/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/sdk/trace/internal/env/%")
select n, "sink site"
