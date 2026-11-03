// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Management;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Grpc;

/// <summary>
/// Validates the <see cref="C.GrpcListener"/> section: a usable port of its own, shared with neither the public
/// listener nor the management listener.
/// </summary>
/// <param name="listeners">The public listener addresses, as declared before any listener was added.</param>
public class GrpcListenerConfigurationValidator(ListenerAddresses listeners) : IValidateOptions<C.AuthProxy>
{
    /// <summary>
    /// The configuration key of the section.
    /// </summary>
    public const string SectionKey = $"{C.AuthProxy.SectionKey}:{nameof(C.AuthProxy.GrpcListener)}";

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        if (options.GrpcListener is not { } grpc)
        {
            return ValidateOptionsResult.Success;
        }

        var failure = grpc switch
        {
            { Port: null } => $"{SectionKey}:{nameof(C.GrpcListener.Port)} must name the port the gRPC listener binds. There is no default, because a port is the deployment's own decision.",
            { Port: < 1 or > 65535 } => $"{SectionKey}:{nameof(C.GrpcListener.Port)} is {grpc.Port}, which is not a port number.",
            _ when listeners.Uses(grpc.Port.Value) => $"{SectionKey}:{nameof(C.GrpcListener.Port)} is {grpc.Port}, which AuthProxy already serves the public listener on. That listener speaks HTTP/1.1, which the gRPC listener must not.",
            _ when options.Management?.Port == grpc.Port => $"{SectionKey}:{nameof(C.GrpcListener.Port)} is {grpc.Port}, which is the management listener's port. The private management endpoints would then be reachable through the ingress.",
            _ when string.IsNullOrWhiteSpace(grpc.BindAddress) => $"{SectionKey}:{nameof(C.GrpcListener.BindAddress)} must name an address. Leave it unset for every address.",
            _ => null,
        };

        return failure is null ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failure);
    }
}
