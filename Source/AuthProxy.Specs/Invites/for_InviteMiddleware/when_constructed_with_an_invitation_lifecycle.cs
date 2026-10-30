// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

public class when_constructed_with_an_invitation_lifecycle : given.an_attested_invitation_staging
{
    void Establish()
    {
        var tenantResolver = Substitute.For<ITenantResolver>();
        var lifecycle = new InvitationLifecycle(
            new InviteCompletion(
                _tokenValidator,
                _configurationMonitor,
                _authentication,
                tenantResolver,
                _httpClientFactory,
                _logger,
                null,
                _issuer,
                _protector),
            _configurationMonitor,
            tenantResolver,
            _httpClientFactory,
            _logger,
            _issuer,
            _protector);

        _context.Items["middleware"] = new InviteMiddleware(
            Next,
            lifecycle,
            _tokenValidator,
            _configurationMonitor,
            _authentication,
            _errorPages,
            _logger);
    }

    async Task Because() => await ((InviteMiddleware)_context.Items["middleware"]).InvokeAsync(_context);

    [Fact] void should_authenticate_the_stage_call() => _handler.Request.Headers.Authorization.Parameter.ShouldEqual("stage-attestation");
    [Fact] void should_protect_the_staged_state_for_the_provider_round_trip() => _protector.State.ShouldNotBeNull();
    [Fact] void should_allow_only_the_provider_named_by_the_signed_capability() => _authenticationService.Received(1).ChallengeAsync(_context, OidcProviderScheme.FromName("First"), Arg.Any<AuthenticationProperties?>());
}
