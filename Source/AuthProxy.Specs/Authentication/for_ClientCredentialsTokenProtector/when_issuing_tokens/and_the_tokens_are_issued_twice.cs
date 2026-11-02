// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsTokenProtector.when_issuing_tokens;

public class and_the_tokens_are_issued_twice : given.a_client_credentials_token_protector
{
    ClientCredentialsIssuedTokens _first;
    ClientCredentialsIssuedTokens _second;

    void Because()
    {
        var deadline = Protector.StartFamily(Service);
        _first = Protector.Issue(Service, "orders-api", null, deadline);
        _second = Protector.Issue(Service, "orders-api", null, deadline);
    }

    [Fact] void should_give_distinct_access_tokens() => _first.AccessToken.ShouldNotEqual(_second.AccessToken);
    [Fact] void should_give_the_full_access_lifetime() => _first.ExpiresInSeconds.ShouldEqual(3600);
}
