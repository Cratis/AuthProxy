// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_CratisIdentityProfile;

public class when_the_discovery_document_names_another_issuer : given.a_cratis_identity_realm
{
    DefaultHttpContext _context;
    Exception? _signInFailure;
    string? _endSessionEndpoint;

    protected override string DiscoveredIssuer => "https://attacker.example/realms/products";

    async Task Because()
    {
        _context = NewContext();
        _signInFailure = await Catch.Exception(() => _services.GetRequiredService<IAuthenticationService>()
            .ChallengeAsync(_context, Scheme, new AuthenticationProperties { RedirectUri = "/" }));
        _endSessionEndpoint = await _services.GetRequiredService<IEndSessionEndpointResolver>().Resolve(Scheme, CancellationToken.None);
    }

    [Fact] void should_refuse_to_sign_in() => _signInFailure.ShouldNotBeNull();
    [Fact] void should_not_redirect_to_the_provider() => _context.Response.Headers.Location.ToString().ShouldBeEmpty();
    [Fact] void should_not_trust_its_end_session_endpoint() => _endSessionEndpoint.ShouldBeNull();
}
