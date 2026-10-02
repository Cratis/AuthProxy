// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_OidcClientAssertions;

public class when_the_provider_uses_a_client_secret : given.oidc_client_assertions
{
    Exception _error;

    void Establish()
    {
        _provider.ClientCredential = null;
        _provider.ClientSecret = "client-secret";
    }

    async Task Because() => _error = await Catch.Exception(() => _assertions.Create(Scheme, _provider, TokenEndpoint, CancellationToken.None));

    [Fact] void should_refuse_to_create_an_assertion() => _error.ShouldBeOfExactType<OidcClientCredentialUnavailable>();
}
