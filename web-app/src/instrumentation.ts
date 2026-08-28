import { context, diag, DiagConsoleLogger, DiagLogLevel, propagation } from '@opentelemetry/api';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { MeterProvider, PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
import { BatchSpanProcessor, NodeTracerProvider, ReadableSpan, SpanProcessor } from '@opentelemetry/sdk-trace-node';

import { OTLPLogExporter } from '@opentelemetry/exporter-logs-otlp-http';
import { logs } from '@opentelemetry/api-logs';
import { LoggerProvider, BatchLogRecordProcessor } from '@opentelemetry/sdk-logs';

const GLOBAL_SDK_KEY = '__web_app_otel_sdk__';

declare global {
	// eslint-disable-next-line no-var
	var __web_app_otel_sdk__: { tracer: NodeTracerProvider; meter: MeterProvider; logger: LoggerProvider } | undefined;
}

function parseDiagLogLevel(): DiagLogLevel {
	switch ((process.env.OTEL_LOG_LEVEL ?? '').toLowerCase()) {
		case 'debug':
			return DiagLogLevel.DEBUG;
		case 'info':
			return DiagLogLevel.INFO;
		case 'warn':
			return DiagLogLevel.WARN;
		case 'error':
			return DiagLogLevel.ERROR;
		default:
			return DiagLogLevel.NONE;
	}
}


export async function register(): Promise<void> {
	// NEXT_RUNTIME may be unset at startup in Node; only skip explicit edge runtime.
	if (process.env.NEXT_RUNTIME === 'edge') return;
	console.info('[otel] instrumentation register() invoked');
	if (globalThis[GLOBAL_SDK_KEY]) return;

	const diagLevel = parseDiagLogLevel();
	if (diagLevel !== DiagLogLevel.NONE) {
		diag.setLogger(new DiagConsoleLogger(), diagLevel);
	}

	const resource = resourceFromAttributes({
		'service.name': process.env.OTEL_SERVICE_NAME ?? 'web-app',
	});

	const tracerProvider = new NodeTracerProvider({ resource });

    const baseProcessor = new BatchSpanProcessor(new OTLPTraceExporter());

    const filteringProcessor: SpanProcessor = {
        forceFlush: () => baseProcessor.forceFlush(),
        onStart: (span, parentContext) => baseProcessor.onStart(span, parentContext),
        shutdown: () => baseProcessor.shutdown(),
        onEnd: (span: ReadableSpan) => {
            const name = span.name.toLowerCase();
            const attributes = span.attributes;
            const httpTarget = (attributes['http.target'] ?? attributes['url.path'] ?? '') as string;

            // (SpanKind 1 = SERVER, SpanKind 2 = CLIENT)
            if (span.kind === 1 || span.kind === 2) {
                baseProcessor.onEnd(span);
            }
        }
    };


	tracerProvider.addSpanProcessor(baseProcessor);
	tracerProvider.register();

	const metricReader = new PeriodicExportingMetricReader({ exporter: new OTLPMetricExporter() });
	const meterProvider = new MeterProvider({ resource, readers: [metricReader] });

	const logExporter = new OTLPLogExporter();
	const loggerProvider = new LoggerProvider({ resource });
	loggerProvider.addLogRecordProcessor(new BatchLogRecordProcessor(logExporter));
	logs.setGlobalLoggerProvider(loggerProvider); // Sets the global logger provider required by PinoInstrumentation


	// --- PINO AUTO-INSTRUMENTATION ---
	// Intercepts Pino logging and attaches trace_id/span_id to log payloads
// --- DYNAMICALLY LOAD NODE INSTRUMENTATIONS ---
	if (process.env.NEXT_RUNTIME === 'nodejs') {
		const { registerInstrumentations } = await import('@opentelemetry/instrumentation');
		const { PinoInstrumentation } = await import('@opentelemetry/instrumentation-pino');

		registerInstrumentations({
		tracerProvider,
		instrumentations: [
			new PinoInstrumentation({
			logKeys: {
				traceId: 'trace_id',
				spanId: 'span_id',
				traceFlags: 'trace_flags',
			},
			}),
		],
		});
	}

	console.info('[otel] OpenTelemetry SDK started');
	globalThis[GLOBAL_SDK_KEY] = { tracer: tracerProvider, meter: meterProvider, logger: loggerProvider };
}

export function onRequestError(error: Error): void {
	// Preserve trace context in request-level exception handling where available.
	const carrier: Record<string, string> = {};
	propagation.inject(context.active(), carrier);
	if (Object.keys(carrier).length > 0) {
		console.error('[otel]', error.message, carrier);
		return;
	}
	console.error('[otel]', error.message);
}
