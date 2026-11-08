// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics;
using Cratis.OpenTelemetry;
using OpenTelemetry;

namespace Cratis.AuthProxy.Telemetry;

/// <summary>
/// Extension methods that wire AuthProxy's OpenTelemetry traces and metrics.
/// </summary>
public static class TelemetryExtensions
{
    const string BaggageHeader = "baggage";

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
        builder.AddCratisOpenTelemetry(options => options.ServiceName = WellKnownTelemetryNames.DefaultServiceName);
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
