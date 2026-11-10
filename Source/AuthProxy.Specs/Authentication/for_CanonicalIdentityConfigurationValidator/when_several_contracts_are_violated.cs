// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_CanonicalIdentityConfigurationValidator;

public class when_several_contracts_are_violated : given.a_valid_authentication_configuration
{
    void Establish()
    {
        _authentication.OidcProviders[0].CanonicalIdentity!.Issuer = "https://issuer.example.com";
        _authentication.OAuthProviders[0].CanonicalIdentity!.Issuer = null;
        _authentication.OAuthProviders[0].VerifiedEmailEndpoint = "not a url";
    }

    void Because() => Validate();

    [Fact] void should_report_the_oidc_issuer() => _result.Failures.ShouldContain("Canonical OIDC providers obtain the issuer from the framework-validated token and cannot configure a literal issuer.");
    [Fact] void should_report_the_oauth_issuer() => _result.Failures.ShouldContain("Canonical OAuth providers require an absolute normalized HTTPS issuer, except for loopback development issuers.");
    [Fact] void should_report_the_endpoint() => _result.Failures.ShouldContain("OAuth verified-email endpoints must be absolute HTTPS URLs, except for loopback development endpoints.");
    [Fact] void should_report_exactly_three_failures() => _result.Failures.Count().ShouldEqual(3);
}
