// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware.sharing_a_prefix_with_client_credentials;

public class when_no_usable_credential_is_presented : given.a_bearer_route_sharing_its_prefix_with_client_credentials
{
    DefaultHttpContext _missing = default!;
    DefaultHttpContext _twice = default!;

    async Task Because()
    {
        _missing = Request($"{Prefix}/orders");
        var issued = Issue(IssuedFor);
        _twice = Request($"{Prefix}/orders", $"Bearer {issued}", $"Bearer {issued}");
        await Middleware.InvokeAsync(_missing);
        await Middleware.InvokeAsync(_twice);
    }

    [Fact] void should_challenge_a_missing_credential() => _missing.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_send_exactly_one_challenge() => _missing.Response.Headers.WWWAuthenticate.Count.ShouldEqual(1);
    [Fact] void should_name_the_resource_metadata() => Challenge(_missing).ShouldContain($"resource_metadata=\"{ResourceMetadataUrl}\"");
    [Fact] void should_refuse_duplicate_credentials() => _twice.Response.StatusCode.ShouldEqual(BearerChallenge.MultipleCredentialsStatusCode);
    [Fact] void should_judge_neither() => Validator.ReceivedCalls().ShouldBeEmpty();
    [Fact] void should_hand_neither_on() => Next.ReceivedCalls().ShouldBeEmpty();
}
