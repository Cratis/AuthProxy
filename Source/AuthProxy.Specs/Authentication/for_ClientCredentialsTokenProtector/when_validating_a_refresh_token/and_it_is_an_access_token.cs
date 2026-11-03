// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsTokenProtector.when_validating_a_refresh_token;

public class and_it_is_an_access_token : given.a_client_credentials_token_protector
{
    bool _valid;

    void Because()
    {
        var issued = Protector.Issue(Service, "orders-api", null, Protector.StartFamily(Service));
        _valid = Protector.TryValidateRefreshToken(issued.AccessToken, out _);
    }

    [Fact] void should_be_invalid() => _valid.ShouldBeFalse();
}
