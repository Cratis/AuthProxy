// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Http.Features;

namespace Cratis.AuthProxy.Scenarios.when_denied_paths_are_configured;

public class and_a_public_path_is_requested(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    readonly List<HttpContext> _denied = [];
    int _callsAfterDenied;
    int _callsAfterAllowed;

    public async ValueTask InitializeAsync()
    {
        var initialCalls = factory.Calls.Count;

        // Send the original target directly: HttpClient's Uri canonicalizes dot segments before sending.
        // TestServer does not populate RawTarget on this path; Kestrel does on real requests.
        foreach (var path in new[]
        {
            "/internal/x", "/INTERNAL/x", "/Internal", "//internal/x", "///internal//x",
            "/%69nternal/x", "/%2Finternal/x", "/foo/../internal/x", "/./internal/x",
            "/foo/%2E%2E/internal/x", "/%252Finternal", "\\internal\\x", "/%5Cinternal",
            "/internal/x?code=secret", "/.auth/login", "/assets/app.js", "/grpc/service/method",
        })
        {
            _denied.Add(await factory.Server.SendAsync(context =>
            {
                context.Features.Get<IHttpRequestFeature>().RawTarget = path;
                context.Request.Path = "/internal/x";
                context.Request.PathBase = "/shared";
            }));
        }

        _callsAfterDenied = factory.Calls.Count - initialCalls;
        foreach (var path in new[] { "/internalx", "/api/internal/x", "/public?next=/internal" })
        {
            await factory.Server.SendAsync(context =>
            {
                context.Features.Get<IHttpRequestFeature>().RawTarget = path;
                context.Request.Path = path.Split('?')[0];
            });
        }

        _callsAfterAllowed = factory.Calls.Count - initialCalls;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact] public void should_return_404_before_login_static_assets_or_grpc() => _denied.TrueForAll(_ => _.Response.StatusCode == StatusCodes.Status404NotFound).ShouldBeTrue();
    [Fact] public void should_not_redirect_or_set_cookies() => _denied.TrueForAll(_ => _.Response.Headers.Count == 0).ShouldBeTrue();
    [Fact] public void should_not_run_authentication_for_a_denied_request() => _callsAfterDenied.ShouldEqual(0);
    [Fact] public void should_still_run_authentication_for_non_denied_paths() => _callsAfterAllowed.ShouldEqual(3);
}
