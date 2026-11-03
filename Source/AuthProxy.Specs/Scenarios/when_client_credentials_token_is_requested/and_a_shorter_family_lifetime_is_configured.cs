// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Scenarios.when_client_credentials_token_is_requested;

[Collection(ClientCredentialsScenarioCollection.Name)]
public class and_a_shorter_family_lifetime_is_configured : Specification
{
    sealed class OneDayFactory : ClockedAuthProxyFactory
    {
        protected override string? FamilyLifetime => "1.00:00:00";
    }

    TokenResponse _response;

    async Task Establish()
    {
        var factory = new OneDayFactory();
        using var client = factory.CreateTestClient();
        var initial = await TokenEndpoint.RequestAsync(client);
        factory.Time.Advance(TimeSpan.FromDays(1));
        _response = await TokenEndpoint.RefreshAsync(client, initial.RefreshToken);
    }

    [Fact] void should_be_unauthorized() => _response.Status.ShouldEqual(HttpStatusCode.Unauthorized);
    [Fact] void should_report_an_invalid_grant() => _response.Error.ShouldEqual("invalid_grant");
}
