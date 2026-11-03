// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsTokenProtector.when_validating_a_refresh_token;

public class and_it_was_not_used_for_thirty_days : given.a_client_credentials_token_protector
{
    protected override TimeSpan FamilyLifetime => TimeSpan.FromDays(90);

    bool _valid;

    void Because()
    {
        var issued = Protector.Issue(Service, "orders-api", null, Protector.StartFamily(Service));
        Time.Advance(TimeSpan.FromDays(30));
        _valid = Protector.TryValidateRefreshToken(issued.RefreshToken, out _);
    }

    [Fact] void should_be_invalid() => _valid.ShouldBeFalse();
}
