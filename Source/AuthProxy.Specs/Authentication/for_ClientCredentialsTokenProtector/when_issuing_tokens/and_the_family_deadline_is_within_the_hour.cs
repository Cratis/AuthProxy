// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsTokenProtector.when_issuing_tokens;

public class and_the_family_deadline_is_within_the_hour : given.a_client_credentials_token_protector
{
    ClientCredentialsIssuedTokens _issued;

    void Because() => _issued = Protector.Issue(Service, "orders-api", null, Time.GetUtcNow().AddMinutes(10));

    [Fact] void should_not_outlive_the_deadline() => _issued.ExpiresInSeconds.ShouldEqual(600);
}
