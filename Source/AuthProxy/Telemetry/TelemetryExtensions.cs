// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics;
using Cratis.OpenTelemetry;
using OpenTelemetry;
using OpenTelemetry.Instrumentation.AspNetCore;
using OpenTelemetry.Instrumentation.Http;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace Cratis.AuthProxy.Telemetry;

/// <summary>
/// Extension methods that wire AuthProxy's OpenTelemetry traces and metrics.
/// </summary>
public static class TelemetryExtensions
{
    const string BaggageHeader = "baggage";
    const string LegacyBaggageHeader = "Correlation-Context";

    /// <summary>Loggers that write the request path, the query or a full outgoing URL. They stay on the console as configured, but are not exported below Warning.</summary>
    static readonly string[] _pathLoggingCategories =
    [
        "Microsoft.AspNetCore.Hosting",
        "Microsoft.AspNetCore.Routing",
        "Microsoft.AspNetCore.Server.Kestrel",
        "Yarp",
        "System.Net.Http.HttpClient"
    ];

    /// <summary>The HTTP client metrics name the host they called, which can carry a tenant; everything else they tag is kept.</summary>
    static readonly string[] _httpClientMetricTags =
    [
        "http.request.method",
        "http.response.status_code",
        "error.type",
        "network.protocol.version",
        "url.scheme",
        "http.connection.state"
    ];

    static readonly string[] _httpClientMeters = ["System.Net.Http", "System.Net.NameResolution", "OpenTelemetry.Instrumentation.Http"];

    /// <summary>
    /// Adds the shared Cratis OpenTelemetry setup.
    /// </summary>
    /// <remarks>
    /// Nothing is exported unless the standard <c language="text">OTEL_EXPORTER_OTLP_ENDPOINT</c> variable (or one of its siblings)
    /// is set, and <c language="text">OTEL_SERVICE_NAME</c> wins over the default <see cref="WellKnownTelemetryNames.DefaultServiceName"/>.
    /// </remarks>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/> for chaining.</returns>
    public static WebApplicationBuilder AddTelemetry(this WebApplicationBuilder builder)
    {
        // Register before the shared setup so sanitization runs before both batch and simple exporters.
        // Instrumentation enrichment is not a security boundary: it can throw, and the runtime can add
        // exception events independently of the instrumentation's RecordException option.
        builder.Services.ConfigureOpenTelemetryTracerProvider(provider => provider.AddProcessor(new TelemetryActivityProcessor()));
        builder.Services.ConfigureOpenTelemetryLoggerProvider(provider => provider.AddProcessor(new TelemetryLogProcessor()));
        builder.AddCratisOpenTelemetry(options => options.ServiceName = WellKnownTelemetryNames.DefaultServiceName);

        // The shared instrumentation records the request URL, the host and exceptions. Those carry invitation
        // tokens, callback codes and tenants, so they are redacted before any exporter sees the span.
        builder.Services.PostConfigure<AspNetCoreTraceInstrumentationOptions>(options =>
        {
            var request = options.EnrichWithHttpRequest;
            var response = options.EnrichWithHttpResponse;
            options.RecordException = false;
            options.EnrichWithHttpRequest = (activity, httpRequest) =>
            {
                request?.Invoke(activity, httpRequest);
                TelemetryRedaction.Redact(activity);
            };
            options.EnrichWithHttpResponse = (activity, httpResponse) =>
            {
                response?.Invoke(activity, httpResponse);
                TelemetryRedaction.Redact(activity);
            };
        });
        builder.Services.PostConfigure<HttpClientTraceInstrumentationOptions>(options =>
        {
            var request = options.EnrichWithHttpRequestMessage;
            var response = options.EnrichWithHttpResponseMessage;
            options.RecordException = false;
            options.EnrichWithHttpRequestMessage = (activity, message) =>
            {
                request?.Invoke(activity, message);
                TelemetryRedaction.Redact(activity);
            };
            options.EnrichWithHttpResponseMessage = (activity, message) =>
            {
                response?.Invoke(activity, message);
                TelemetryRedaction.Redact(activity);
            };
        });

        // The shared setup exports log scopes, and the hosting scope of a request carries its path (an invitation token).
        builder.Services.PostConfigure<OpenTelemetryLoggerOptions>(options => options.IncludeScopes = false);
        foreach (var category in _pathLoggingCategories)
        {
            builder.Logging.AddFilter<OpenTelemetryLoggerProvider>(category, LogLevel.Warning);
        }

        builder.Services.ConfigureOpenTelemetryMeterProvider(provider => provider.AddView(instrument =>
            _httpClientMeters.Contains(instrument.Meter.Name, StringComparer.Ordinal)
                ? new MetricStreamConfiguration { TagKeys = _httpClientMetricTags }
                : null));
        return builder;
    }

    /// <summary>
    /// Keeps the caller's W3C <c language="text">baggage</c> out of the proxy, so what a caller attaches to a request can never travel on to a service.
    /// </summary>
    /// <remarks>
    /// The W3C <c language="text">traceparent</c> and <c language="text">tracestate</c> headers are untouched: they continue the caller's trace through the
    /// proxy to the service. Only baggage — arbitrary key-value pairs the caller controls — is dropped, both as
    /// the header and as the ambient context the HTTP client instrumentation would otherwise write back out.
    /// </remarks>
    /// <param name="app">The <see cref="WebApplication"/> to configure.</param>
    /// <returns>The same <see cref="WebApplication"/> for chaining.</returns>
    public static WebApplication UseTelemetryBaggageStripping(this WebApplication app)
    {
        app.Use((context, next) =>
        {
            context.Request.Headers.Remove(BaggageHeader);
            context.Request.Headers.Remove(LegacyBaggageHeader);
            Baggage.Current = default;

            // ASP.NET Core parses the header into the request activity before any middleware runs, and the HTTP
            // client writes that activity's baggage back out, so it has to be cleared there as well.
            var activity = Activity.Current;
            if (activity is not null)
            {
                foreach (var item in activity.Baggage.ToArray())
                {
                    activity.SetBaggage(item.Key, null);
                }
            }

            return next(context);
        });
        return app;
    }
}
