// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware.sharing_a_prefix_with_client_credentials;

/// <summary>
/// Tampered and foreign tokens are judged by bearer validation. An expired token minted by this deployment
/// is recognized and refused without external validation. None reaches the client-credentials handoff.
/// </summary>
public class when_a_token_cannot_be_verified_as_issued : given.a_bearer_route_sharing_its_prefix_with_client_credentials
{
    DefaultHttpContext[] _contexts = default!;

    async Task Because()
    {
        var issued = Issue(IssuedFor);
        var middle = issued.Length / 2;
        var tampered = string.Concat(issued.AsSpan(0, middle), issued[middle] == 'A' ? "B" : "A", issued.AsSpan(middle + 1));
        var expired = new ClientCredentialsTokenProtector(DataProtection, new Authentication.for_ClientCredentialsTokenProtector.given.ManualTime(DateTimeOffset.UtcNow.AddHours(-2))).CreateToken(IssuedFor, "orders-client");
        var foreign = new ClientCredentialsTokenProtector(new EphemeralDataProtectionProvider()).CreateToken(IssuedFor, "orders-client");

        _contexts = [.. new[] { tampered, expired, foreign }.Select(token => Request($"{Prefix}/orders", $"Bearer {token}"))];
        foreach (var context in _contexts)
        {
            await Middleware.InvokeAsync(context);
        }
    }

    [Fact] void should_refuse_each() => _contexts.All(_ => _.Response.StatusCode == StatusCodes.Status401Unauthorized).ShouldBeTrue();
    [Fact]
    async Task should_only_judge_the_altered_and_foreign_tokens_externally()
    {
        Validator.ReceivedCalls().Count().ShouldEqual(2);
        await Validator.Received(1).Validate(_contexts[0].Request, Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>());
        await Validator.Received(1).Validate(_contexts[2].Request, Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>());
        await Validator.DidNotReceive().Validate(_contexts[1].Request, Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>());
    }

    [Fact] void should_never_forward() => Forwarder.ReceivedCalls().ShouldBeEmpty();
    [Fact] void should_never_hand_one_on_as_issued() => Next.ReceivedCalls().ShouldBeEmpty();
    [Fact] void should_not_mark_one_as_verified() => _contexts.Any(_ => _.Items.ContainsKey(ClientCredentialsDefaults.ValidatedTokenPayloadItemKey)).ShouldBeFalse();
}
