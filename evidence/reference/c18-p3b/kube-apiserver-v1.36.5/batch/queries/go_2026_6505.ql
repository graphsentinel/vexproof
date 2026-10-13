/**
 * @name sinkgen GO-2026-6505: untrusted data reaches the vulnerable symbol's input
 * @kind path-problem
 * @problem.severity warning
 * @id vexproof/sinkgen-go-2026-6505
 */

import go

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    // template v3: a *http.Request read inside an HTTP client's round trip is the program's own outgoing request,
    // not remote input (batch run on metrics-server: 3 of 4 paths came from there)
    // heuristic, by function name and by HTTP client implementation file
    n instanceof RemoteFlowSource and
    not n.getRoot().(FuncDef).getName().regexpMatch("(?i).*(roundtrip|dial).*") and
    not n.getFile().getAbsolutePath()
        .regexpMatch(".*/(x/net/http2/transport[^/]*|net/http/(transport|client)[^/]*|grpc/internal/transport/http2_client)[.]go")
    or
    exists(Field f | f.hasQualifiedName("net/http", "Response", "Body") | n = f.getARead())
  }

  predicate isSink(DataFlow::Node n) {
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
  }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode src, Flow::PathNode sink
where Flow::flowPath(src, sink)
select sink.getNode(), src, sink, "untrusted data reaches a GO-2026-6505 sink", src.getNode(), "source"
