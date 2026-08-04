// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Cratis.AuthProxy.for_EndSessionEndpointResolver;

public class when_resolving_for_an_oauth_provider : Specification
{
    EndSessionEndpointResolver _resolver;
    IOptionsMonitor<OpenIdConnectOptions> _oidcOptions;
    string? _result;

    void Establish()
    {
        // GitHub is an OAuth 2.0 provider, not an OIDC provider, so it has no end-session endpoint and must
        // resolve to null without inspecting the OIDC options at all.
        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OAuthProviders = [new C.OAuthProvider { Name = "GitHub" }],
        });

        _oidcOptions = Substitute.For<IOptionsMonitor<OpenIdConnectOptions>>();

        _resolver = new EndSessionEndpointResolver(authConfig, _oidcOptions, Substitute.For<ILogger<EndSessionEndpointResolver>>());
    }

    async Task Because() => _result = await _resolver.Resolve("github", CancellationToken.None);

    [Fact] void should_not_resolve_an_endpoint() => _result.ShouldBeNull();
    [Fact] void should_not_inspect_the_oidc_options() => _oidcOptions.DidNotReceive().Get(Arg.Any<string>());
}
