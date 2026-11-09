// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware.sharing_a_prefix_with_client_credentials;

/// <summary>
/// A token that only looks issued — tampered with, expired, or protected by another key ring — is not verifiably
/// AuthProxy's, so it never reaches the client-credentials rules. Bearer validation alone judges it, and refuses it.
/// </summary>
public class when_a_token_cannot_be_verified_as_issued : given.a_bearer_route_sharing_its_prefix_with_client_credentials
{
    DefaultHttpContext[] _contexts = default!;

    async Task Because()
    {
        var issued = Issue(IssuedFor);
        var middle = issued.Length / 2;
        var tampered = string.Concat(issued.AsSpan(0, middle), issued[middle] == 'A' ? "B" : "A", issued.AsSpan(middle + 1));
        var expired = new ClientCredentialsTokenProtector(DataProtection, new global::Cratis.AuthProxy.Authentication.for_ClientCredentialsTokenProtector.given.ManualTime(DateTimeOffset.UtcNow.AddHours(-2))).CreateToken(IssuedFor, "orders-client");
        var foreign = new ClientCredentialsTokenProtector(new EphemeralDataProtectionProvider()).CreateToken(IssuedFor, "orders-client");

        _contexts = [.. new[] { tampered, expired, foreign }.Select(token => Request($"{Prefix}/orders", $"Bearer {token}"))];
        foreach (var context in _contexts)
        {
            await Middleware.InvokeAsync(context);
        }
    }

    [Fact] void should_refuse_each() => _contexts.All(_ => _.Response.StatusCode == StatusCodes.Status401Unauthorized).ShouldBeTrue();
    [Fact] void should_judge_each_once_as_a_bearer_token() => Validator.ReceivedCalls().Count().ShouldEqual(_contexts.Length);
    [Fact] void should_never_hand_one_on_as_issued() => Next.ReceivedCalls().ShouldBeEmpty();
    [Fact] void should_not_mark_one_as_verified() => _contexts.Any(_ => _.Items.ContainsKey(ClientCredentialsDefaults.ValidatedTokenPayloadItemKey)).ShouldBeFalse();
}
