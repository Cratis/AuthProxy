// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using Cratis.AuthProxy.Management;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Grpc;

/// <summary>
/// Opens the HTTP/2-only listener an ingress hands gRPC calls to (<see cref="C.GrpcListener"/>).
/// </summary>
public static class GrpcListenerExtensions
{
    /// <summary>
    /// Adds the listener when the section names a port. Must follow <c language="csharp">AddManagement</c>, so the management listener's
    /// address is kept.
    /// </summary>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/>.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/>.</returns>
    public static WebApplicationBuilder AddGrpcListener(this WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<IValidateOptions<C.AuthProxy>, GrpcListenerConfigurationValidator>();

        var grpc = builder.Configuration.GetSection(GrpcListenerConfigurationValidator.SectionKey).Get<C.GrpcListener>();
        if (grpc?.Port is not { } port)
        {
            return builder;
        }

        // The addresses as they stand now, after the management listener added its own - replacing them with the
        // public ones alone would close it.
        var current = builder.WebHost.GetSetting(WebHostDefaults.ServerUrlsKey) is { Length: > 0 } urls
            ? urls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : [.. ListenerAddresses.Resolve(builder.Configuration).Declared];
        builder.WebHost.UseUrls([.. current, $"http://{grpc.BindAddress}:{port.ToString(CultureInfo.InvariantCulture)}"]);
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.ConfigureEndpointDefaults(listen =>
        {
            if (listen.IPEndPoint?.Port == port)
            {
                listen.Protocols = HttpProtocols.Http2;
            }
        }));

        return builder;
    }

    /// <summary>
    /// Lifts the request body limit for gRPC calls on the listener. A streaming call's request body is every message
    /// the client sends for as long as the call is open, so a limit on its total size ends a long-lived stream
    /// mid-call; each message is bounded by the gRPC service itself instead.
    /// </summary>
    /// <param name="app">The <see cref="WebApplication"/>.</param>
    /// <returns>The same <see cref="WebApplication"/>.</returns>
    public static WebApplication UseGrpcListener(this WebApplication app)
    {
        var grpc = app.Configuration.GetSection(GrpcListenerConfigurationValidator.SectionKey).Get<C.GrpcListener>();
        if (grpc?.Port is not { } port)
        {
            return app;
        }

        app.Use(async (context, next) =>
        {
            if (GrpcRequests.IsStreamOnListener(context, port) && context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } limit)
            {
                limit.MaxRequestBodySize = null;
            }

            await next(context);
        });

        return app;
    }
}
