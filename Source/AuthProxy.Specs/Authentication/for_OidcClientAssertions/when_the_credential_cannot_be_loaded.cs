// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_OidcClientAssertions;

public class when_the_credential_cannot_be_loaded : given.oidc_client_assertions
{
    Exception _error;

    void Establish()
    {
        _provider.ClientCredential!.Source = C.OidcClientCredentialSource.CertificateFile;
        _provider.ClientCredential.CertificatePath = Path.Combine(_directory, "missing.pfx");
    }

    async Task Because() => _error = await Catch.Exception(() => _assertions.Create(Scheme, _provider, TokenEndpoint, CancellationToken.None));

    [Fact] void should_fail_with_an_unavailable_credential() => _error.ShouldBeOfExactType<OidcClientCredentialUnavailable>();
    [Fact] void should_name_the_provider() => _error.Message.ShouldContain("Workforce");
}
