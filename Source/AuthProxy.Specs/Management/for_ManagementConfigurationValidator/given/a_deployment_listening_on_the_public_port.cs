// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Management.for_ManagementConfigurationValidator.given;

/// <summary>
/// A deployment serving traffic on the port the container images publish, and the validator that judges
/// what it asks for on top of that.
/// </summary>
public class a_deployment_listening_on_the_public_port : Specification
{
    protected const int PublicPort = 8080;
    protected ManagementConfigurationValidator _validator;
    protected ValidateOptionsResult _result;

    void Establish() => _validator = new ManagementConfigurationValidator(
        ListenerAddresses.Resolve(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["urls"] = $"http://+:{PublicPort}" })
            .Build()));

    protected void Validate(C.Management? management) =>
        _result = _validator.Validate(null, new C.AuthProxy { Management = management });
}
