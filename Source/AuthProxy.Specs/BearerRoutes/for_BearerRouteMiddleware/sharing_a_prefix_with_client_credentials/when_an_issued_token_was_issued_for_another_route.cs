// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware.sharing_a_prefix_with_client_credentials;

/// <summary>
/// A token AuthProxy issued for another route prefix, or for another service, is AuthProxy's own: the
/// client-credentials rules refuse it, and it is never offered to bearer validation as a second chance.
/// </summary>
public class when_an_issued_token_was_issued_for_another_route : given.a_bearer_route_sharing_its_prefix_with_client_credentials
{
    DefaultHttpContext _otherPrefix = default!;
    DefaultHttpContext _otherService = default!;

    async Task Because()
    {
        _otherPrefix = Request($"{Prefix}/orders", $"Bearer {Issue(new ConfiguredClientCredentialsService(ServiceName, "/other", IssuedFor.VerificationUri))}");
        _otherService = Request($"{Prefix}/orders", $"Bearer {Issue(new ConfiguredClientCredentialsService("billing", Prefix, IssuedFor.VerificationUri))}");
        await Middleware.InvokeAsync(_otherPrefix);
        await Middleware.InvokeAsync(_otherService);
    }

    [Fact] void should_refuse_a_token_for_another_prefix() => _otherPrefix.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_refuse_a_token_for_another_service() => _otherService.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_answer_with_the_route_challenge() => Challenge(_otherPrefix).ShouldContain($"resource_metadata=\"{ResourceMetadataUrl}\"");
    [Fact] void should_not_retry_either_as_a_bearer_token() => Validator.ReceivedCalls().ShouldBeEmpty();
    [Fact] void should_not_hand_either_on() => Next.ReceivedCalls().ShouldBeEmpty();
}
