// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware.sharing_a_prefix_with_client_credentials;

public class when_an_issued_token_has_expired : given.a_bearer_route_sharing_its_prefix_with_client_credentials
{
    string _token = string.Empty;
    DefaultHttpContext _context = default!;

    async Task Because()
    {
        _token = Issue(IssuedFor);
        Clock.Advance(TimeSpan.FromHours(2));
        _context = Request("/api/tools", $"Bearer {_token}");
        await Middleware.InvokeAsync(_context);
    }

    [Fact] void should_still_recognize_the_deployment_purpose_chain() => TokenProtector.IsIssued(_token).ShouldBeTrue();
    [Fact] void should_not_validate_the_expired_token() => TokenProtector.TryValidate(_token, out _).ShouldBeFalse();
    [Fact] void should_refuse_the_token() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_challenge_as_invalid() => Challenge(_context).ShouldEqual($"Bearer error=\"invalid_token\", resource_metadata=\"{ResourceMetadataUrl}\"");
    [Fact] void should_never_try_external_validation() => Validator.ReceivedCalls().ShouldBeEmpty();
    [Fact] void should_never_forward() => Forwarder.ReceivedCalls().ShouldBeEmpty();
    [Fact] void should_never_hand_on() => Next.ReceivedCalls().ShouldBeEmpty();
}
