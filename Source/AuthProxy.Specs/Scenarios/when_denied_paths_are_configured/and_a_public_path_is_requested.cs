// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_denied_paths_are_configured;

public class and_a_public_path_is_requested(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    readonly List<HttpContext> _denied = [];
    int _callsAfterDenied;
    int _callsAfterAllowed;

    public async ValueTask InitializeAsync()
    {
        var initialCalls = factory.Calls.Count;

        // TestServer does not parse request targets like Kestrel: supply downstream Path values here.
        // The loopback Kestrel specs separately exercise decoding and dot-segment resolution.
        foreach (var path in new[]
        {
            "/internal/x", "/INTERNAL/x", "/Internal", "//internal/x", "///internal//x",
            "/internal%2Fx", "/internal\\x", "/%5Cinternal",
            "/.auth/login", "/assets/app.js", "/grpc/service/method",
        })
        {
            _denied.Add(await factory.Server.SendAsync(context => context.Request.Path = path));
        }

        _callsAfterDenied = factory.Calls.Count - initialCalls;
        foreach (var path in new[] { "/internalx", "/api/internal/x", "/public?next=/internal" })
        {
            await factory.Server.SendAsync(context => context.Request.Path = path.Split('?')[0]);
        }

        _callsAfterAllowed = factory.Calls.Count - initialCalls;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact] public void should_return_404_before_login_static_assets_or_grpc() => _denied.TrueForAll(_ => _.Response.StatusCode == StatusCodes.Status404NotFound).ShouldBeTrue();
    [Fact] public void should_not_redirect_or_set_cookies() => _denied.TrueForAll(_ => _.Response.Headers.Count == 0).ShouldBeTrue();
    [Fact] public void should_not_run_authentication_for_a_denied_request() => _callsAfterDenied.ShouldEqual(0);
    [Fact] public void should_still_run_authentication_for_non_denied_paths() => _callsAfterAllowed.ShouldEqual(3);
}
