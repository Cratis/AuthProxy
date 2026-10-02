// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_the_provider_authenticates_with_a_client_assertion : given.user_access_tokens
{
    async Task Because()
    {
        _provider.ClientSecret = string.Empty;
        _provider.ClientCredential = new() { Source = C.OidcClientCredentialSource.ManagedIdentity };
        _options.ClientSecret = null;
        _assertions.Create(Scheme, Arg.Any<C.OidcProvider>(), TokenEndpointUrl, Arg.Any<CancellationToken>()).Returns("signed-assertion");
        await Get();
    }

    [Fact] void should_send_the_assertion() => _endpoint.Received[0]["client_assertion"].ShouldEqual("signed-assertion");
    [Fact] void should_declare_a_jwt_assertion() => _endpoint.Received[0]["client_assertion_type"].ShouldEqual("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    [Fact] void should_send_no_client_secret() => _endpoint.Received[0].ContainsKey("client_secret").ShouldBeFalse();
}
