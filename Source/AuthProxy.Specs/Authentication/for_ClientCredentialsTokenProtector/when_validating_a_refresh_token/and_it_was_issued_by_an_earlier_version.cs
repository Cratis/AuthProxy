// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsTokenProtector.when_validating_a_refresh_token;

public class and_it_was_issued_by_an_earlier_version : given.a_client_credentials_token_protector
{
    DateTimeOffset _expectedDeadline;
    bool _valid;
    ClientCredentialsTokenPayload _payload;

    void Because()
    {
        var earlier = DataProtection
            .CreateProtector("Cratis.AuthProxy.Authentication.ClientCredentials.Refresh.v1")
            .ToTimeLimitedDataProtector();
        var json = JsonSerializer.Serialize(new { service = "portal", routePrefix = "/api", clientId = "orders-api" });
        _expectedDeadline = Time.GetUtcNow().AddDays(5);
        var token = earlier.Protect(json, _expectedDeadline);

        _valid = Protector.TryValidateRefreshToken(token, out _payload);
    }

    [Fact] void should_be_valid() => _valid.ShouldBeTrue();
    [Fact] void should_use_its_own_expiry_as_the_deadline() => _payload.FamilyExpiresAt.ShouldEqual(_expectedDeadline);
}
