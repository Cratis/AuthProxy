// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsTokenProtector.when_validating_a_refresh_token;

public class and_the_family_deadline_has_not_passed : given.a_client_credentials_token_protector
{
    DateTimeOffset _deadline;
    bool _valid;
    ClientCredentialsTokenPayload _payload;

    void Because()
    {
        _deadline = Protector.StartFamily(Service);
        var issued = Protector.Issue(Service, "orders-api", null, _deadline);
        Time.Advance(TimeSpan.FromDays(29));
        _valid = Protector.TryValidateRefreshToken(issued.RefreshToken, out _payload);
    }

    [Fact] void should_be_valid() => _valid.ShouldBeTrue();
    [Fact] void should_carry_the_issued_deadline() => _payload.FamilyExpiresAt.ShouldEqual(_deadline);
}
