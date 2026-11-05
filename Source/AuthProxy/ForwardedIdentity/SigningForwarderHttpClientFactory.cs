// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Forwarder;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Preserves YARP's transport configuration while signing at the final send boundary.</summary>
/// <param name="logger">The YARP client-factory logger.</param>
/// <param name="signer">The v1 signer.</param>
internal sealed class SigningForwarderHttpClientFactory(ILogger<ForwarderHttpClientFactory> logger, IForwardedIdentitySigner signer) : ForwarderHttpClientFactory(logger)
{
    readonly ILogger _logger = logger;

    /// <inheritdoc/>
    protected override void ConfigureHandler(ForwarderHttpClientContext context, SocketsHttpHandler handler)
    {
        base.ConfigureHandler(context, handler);
        handler.KeepAlivePingPolicy = HttpKeepAlivePingPolicy.Always;
        handler.KeepAlivePingDelay = TimeSpan.FromMinutes(1);
        handler.KeepAlivePingTimeout = TimeSpan.FromMinutes(2);
        handler.ConnectTimeout = TimeSpan.FromMinutes(3);
    }

    /// <inheritdoc/>
    protected override HttpMessageHandler WrapHandler(ForwarderHttpClientContext context, HttpMessageHandler handler) =>
        new ForwardedIdentitySigningHandler(signer, _logger) { InnerHandler = base.WrapHandler(context, handler) };
}
