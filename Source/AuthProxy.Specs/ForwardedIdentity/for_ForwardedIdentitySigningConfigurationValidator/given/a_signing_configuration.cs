// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningConfigurationValidator.given;

public class a_signing_configuration : Specification
{
    protected C.ForwardedIdentitySigning settings;
    protected C.AuthProxy configuration;
    protected ValidateOptionsResult result;

    void Establish()
    {
        settings = new() { Audience = "spec-backend", KeyId = "active-1", SecretBase64 = Convert.ToBase64String(Enumerable.Repeat((byte)42, 32).ToArray()) };
        configuration = new() { Services = new Dictionary<string, C.Service> { ["main"] = new() { ForwardedIdentity = settings } } };
    }

    protected void Validate() => result = new ForwardedIdentitySigningConfigurationValidator().Validate(null, configuration);
}
