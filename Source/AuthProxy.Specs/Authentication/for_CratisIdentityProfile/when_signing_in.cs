// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;

namespace Cratis.AuthProxy.Authentication.for_CratisIdentityProfile;

public class when_signing_in : given.a_cratis_identity_realm
{
    DefaultHttpContext _context;
    string _location;
    Dictionary<string, StringValues> _query;

    async Task Because()
    {
        _context = NewContext();
        await _services.GetRequiredService<IAuthenticationService>()
            .ChallengeAsync(_context, Scheme, new AuthenticationProperties { RedirectUri = "/" });
        _location = _context.Response.Headers.Location.ToString();
        _query = QueryHelpers.ParseQuery(new Uri(_location).Query);
    }

    [Fact] void should_redirect_to_the_discovered_authorization_endpoint() => _location.StartsWith($"{AuthorizationEndpoint}?", StringComparison.Ordinal).ShouldBeTrue();
    [Fact] void should_use_the_authorization_code_flow() => _query["response_type"].ToString().ShouldEqual("code");
    [Fact] void should_identify_the_client() => _query["client_id"].ToString().ShouldEqual("studio-web");
    [Fact] void should_request_only_the_profile_scopes() => _query["scope"].ToString().ShouldEqual("openid profile");
    [Fact] void should_send_a_pkce_challenge() => _query["code_challenge"].ToString().ShouldNotBeEmpty();
    [Fact] void should_use_the_s256_challenge_method() => _query["code_challenge_method"].ToString().ShouldEqual("S256");
    [Fact] void should_send_state() => _query["state"].ToString().ShouldNotBeEmpty();
    [Fact] void should_send_a_nonce() => _query["nonce"].ToString().ShouldNotBeEmpty();
    [Fact] void should_return_to_the_profile_callback() => _query["redirect_uri"].ToString().ShouldEqual($"https://studio.cratis.example/signin-{Scheme}");
    [Fact] void should_not_put_the_client_secret_in_the_redirect() => _location.Contains(ClientSecret, StringComparison.Ordinal).ShouldBeFalse();
    [Fact] void should_not_log_the_client_secret() => _logs.Text.Contains(ClientSecret, StringComparison.Ordinal).ShouldBeFalse();
    [Fact] void should_not_log_the_state() => _logs.Text.Contains(_query["state"].ToString(), StringComparison.Ordinal).ShouldBeFalse();
}
