import go
from DataFlow::Node n
where
  (
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk", "Version") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "NeverSample") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "NewBatchSpanProcessor") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "NewTracerProvider") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "ParentBased") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "Shutdown$1") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "TraceIDRatioBased") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "TracerProvider", "Shutdown") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "TracerProvider", "Tracer") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "WithResource") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "WithSampler") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "WithSpanProcessor") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "errUnsupportedSampler", "Error") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
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
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "nonRecordingSpan", "RecordError") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
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
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "recordingSpan", "RecordError") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
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
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "samplerArgParseError", "Error") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "samplerArgParseError", "Unwrap") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "tracer", "Start") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace", "tracerProviderConfig", "MarshalLog") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace", "Exporter", "ExportSpans") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace", "Exporter", "Shutdown") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace", "New") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace", "Shutdown$1") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace", "Start$1") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace", "Version") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/env", "BatchSpanProcessorExportTimeout") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/env", "BatchSpanProcessorMaxExportBatchSize") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/env", "BatchSpanProcessorMaxQueueSize") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/env", "BatchSpanProcessorScheduleDelay") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/env", "SpanAttributeCount") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/env", "SpanAttributeValueLength") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/env", "SpanEventAttributeCount") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/env", "SpanEventCount") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/env", "SpanLinkAttributeCount") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/env", "SpanLinkCount") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/env", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc", "New") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc", "WithDialOption") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc", "WithEndpoint") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc", "WithInsecure") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc", "client", "Start") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc", "client", "Stop") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc", "client", "UploadTraces") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/observ", "ExportOp", "End") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/observ", "Instrumentation", "ExportSpans") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/observ", "NewInstrumentation") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
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
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/internal/tracetransform", "Spans") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/internal/tracetransform", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/envconfig", "EnvOptionsReader", "Apply") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/envconfig", "WithBool") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/envconfig", "WithCertPool") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/envconfig", "WithClientCert") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/envconfig", "WithDuration") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/envconfig", "WithHeaders") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/envconfig", "WithURL") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/envconfig", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal", "PartialSuccess", "As") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal", "PartialSuccess", "Error") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal", "PartialSuccess", "Is") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal", "TracePartialSuccessError") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/resource", "Default") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/resource", "Default$1") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/resource", "Environment") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/resource", "Merge") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/resource", "New") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/resource", "NewSchemaless$1") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/resource", "Resource", "Equivalent") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/resource", "Resource", "Iter") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/resource", "Resource", "SchemaURL") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/resource", "WithAttributes") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/resource", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/retry", "Config", "RequestFunc") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/retry", "RequestFunc$1") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/retry", "RequestFunc$2") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/retry", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/counter", "NextExporterID") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/counter", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/observ", "BSP", "Processed") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/observ", "BSP", "ProcessedQueueFull") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/observ", "BSP", "Shutdown") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/trace/internal/observ", "NewBSP") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
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
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/x", "Feature[string]", "Enabled") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/x", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Method m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/internal/x", "Feature[string]", "Enabled") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/internal/x", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/otlpconfig", "NewGRPCConfig") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/otlpconfig", "NewGRPCOption") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/otlpconfig", "WithEndpoint") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/otlpconfig", "WithInsecure") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/otlpconfig", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
    or
    exists(Function m | m.hasQualifiedName("go.opentelemetry.io/otel/sdk/instrumentation", "init") | exists(DataFlow::CallNode c | c.getTarget() = m | n = c.getAnArgument() or n = c.getReceiver()))
  ) and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/sdk/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/sdk/trace/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/sdk/trace/internal/env/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/observ/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/internal/tracetransform/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/envconfig/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/sdk/resource/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/retry/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/counter/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/sdk/trace/internal/observ/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/x/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/sdk/internal/x/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc/internal/otlpconfig/%") and not n.getFile().getAbsolutePath().matches("%/go.opentelemetry.io/otel/sdk/instrumentation/%")
select n, "sink site"
