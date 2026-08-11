// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links.for_LinkSubjectExchanger.given;

namespace Cratis.AuthProxy.Links.for_LinkSubjectExchanger;

/// <summary>
/// Some providers hand back a principal that names no provider at all — no issuer claim, and an identity
/// whose authentication type is the meaningless "AuthenticationTypes.Federation". The scheme that was
/// challenged names the provider authoritatively, so the exchange attributes the link to the configured
/// provider behind that scheme.
/// </summary>
public class when_the_scheme_names_the_provider : a_link_subject_exchanger
{
    LinkExchangeResult _result;

    protected override C.AuthProxy CreateConfig()
    {
        var config = base.CreateConfig();
        config.Authentication.OidcProviders.Add(new C.OidcProvider { Name = "Google", Authority = "https://accounts.google.com" });
        return config;
    }

    protected override ClaimsPrincipal CreatePrincipal() => new(new ClaimsIdentity(
        [new Claim("sub", "google-subject-456")],
        "AuthenticationTypes.Federation"));

    async Task Because() => _result = await _exchanger.Exchange(_principal, _properties, "google");

    [Fact] void should_succeed() => _result.ShouldEqual(LinkExchangeResult.Success);
    [Fact] void should_attribute_the_configured_provider_behind_the_scheme() => _handler.LastRequestBody!.ShouldContain("Google");
    [Fact] void should_not_leak_the_authentication_type() => _handler.LastRequestBody!.ShouldNotContain("AuthenticationTypes.Federation");
}
