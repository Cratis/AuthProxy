// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Cratis.AuthProxy.Authentication.for_CanonicalSessionRegistrationFingerprint;

/// <summary>
/// Specifies that configured authorization parameters change the registration fingerprint, and that none leaves it as it was.
/// </summary>
public class when_authorization_parameters_are_configured : Specification
{
    string _without;
    string _withParameter;
    string _withOtherValue;
    string _withParametersInAnotherOrder;
    string _withTheSameParameters;

    void Because()
    {
        var options = new OpenIdConnectOptions { ClientId = "client", MetadataAddress = "https://login.example.com/.well-known/openid-configuration" };
        _without = Fingerprint(options);
        _withParameter = Fingerprint(options, ("connection", "email"));
        _withOtherValue = Fingerprint(options, ("connection", "sms"));
        _withParametersInAnotherOrder = Fingerprint(options, ("a", "1"), ("b", "2"));
        _withTheSameParameters = Fingerprint(options, ("b", "2"), ("a", "1"));
    }

    [Fact] void should_differ_from_a_registration_without_parameters() => _withParameter.ShouldNotEqual(_without);
    [Fact] void should_differ_when_a_value_changes() => _withOtherValue.ShouldNotEqual(_withParameter);
    [Fact] void should_not_depend_on_the_order_of_the_parameters() => _withTheSameParameters.ShouldEqual(_withParametersInAnotherOrder);

    static string Fingerprint(OpenIdConnectOptions options, params (string Key, string Value)[] parameters) =>
        CanonicalSessionRegistrationFingerprint.Create(
            "workforce",
            new C.OidcProvider
            {
                Name = "Workforce",
                Authority = "https://login.example.com",
                ClientId = "client",
                CanonicalIdentity = new C.CanonicalIdentity { ProviderKey = "workforce", SubjectClaimType = "oid" },
                AuthorizationParameters = parameters.ToDictionary(_ => _.Key, _ => _.Value)
            },
            options);
}
