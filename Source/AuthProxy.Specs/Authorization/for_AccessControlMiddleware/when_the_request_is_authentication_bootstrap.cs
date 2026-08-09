// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessControlMiddleware;

/// <summary>
/// The endpoints that establish a session are never gated by the session they establish.
/// <para>
/// The provider list, the per-provider login endpoint and the provider callback are all reached while
/// signing in — and a callback is reached by a caller who has just become authenticated but whose claims
/// are still being assembled. Gating them is a chicken and egg: the only way to acquire the claims runs
/// through the endpoints that would demand them.
/// </para>
/// </summary>
public class when_the_request_is_authentication_bootstrap : given.an_access_control_middleware
{
    bool _providersForwarded;
    bool _loginForwarded;
    bool _callbackForwarded;

    void Establish()
    {
        CallerCarrying(new Claim("urn:github:organization", "some-other-org"));
        BuildMiddleware();
    }

    async Task Because()
    {
        _context.Request.Path = WellKnownPaths.Providers;
        await _middleware.InvokeAsync(_context);
        _providersForwarded = _nextCalled;

        _nextCalled = false;
        _context.Request.Path = $"{WellKnownPaths.LoginPrefix}/github";
        await _middleware.InvokeAsync(_context);
        _loginForwarded = _nextCalled;

        _nextCalled = false;
        _context.Request.Path = "/signin-github";
        await _middleware.InvokeAsync(_context);
        _callbackForwarded = _nextCalled;
    }

    [Fact] void should_forward_the_providers_endpoint() => _providersForwarded.ShouldBeTrue();
    [Fact] void should_forward_the_login_endpoint() => _loginForwarded.ShouldBeTrue();
    [Fact] void should_forward_the_provider_callback() => _callbackForwarded.ShouldBeTrue();
}
