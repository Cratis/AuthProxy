// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Management;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Grpc.for_GrpcListenerConfigurationValidator.given;

/// <summary>
/// A deployment serving traffic on the port the container images publish, and the validator that judges the gRPC
/// listener it asks for on top of that.
/// </summary>
public class a_deployment_listening_on_the_public_port : Specification
{
    protected const int PublicPort = 8080;
    protected GrpcListenerConfigurationValidator _validator;
    protected ValidateOptionsResult _result;

    void Establish() => _validator = new GrpcListenerConfigurationValidator(
        ListenerAddresses.Resolve(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["urls"] = $"http://+:{PublicPort}" })
            .Build()));

    protected void Validate(C.GrpcListener? grpc, C.Management? management = null) =>
        _result = _validator.Validate(null, new C.AuthProxy { GrpcListener = grpc, Management = management });
}
