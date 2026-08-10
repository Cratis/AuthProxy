// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessControlMiddleware.given;

/// <summary>
/// The middleware wired to the real policy, in front of a next that records whether it ran.
/// <para>
/// The policy is the real one rather than a substitute: what these specs are about is which requests the
/// middleware submits to it at all, and a substitute would answer the same way for a request that should
/// never have reached it — making a skipped check indistinguishable from a passed one.
/// </para>
/// </summary>
public class an_access_control_middleware : Specification
{
    protected const string AnonymousPath = "/api/webhooks/payments";

    protected AccessControlMiddleware _middleware;
    protected DefaultHttpContext _context;
    protected IErrorPageProvider _errorPageProvider;
    protected C.AuthProxy _config;
    protected bool _nextCalled;

    void Establish()
    {
        _config = new C.AuthProxy
        {
            Authorization = new C.Authorization
            {
                RequiredClaims = [new C.ClaimRequirement { Claim = "urn:github:organization", AnyOf = ["Cratis"] }],
            },
            Services = new Dictionary<string, C.Service>
            {
                ["main"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://backend.test/" },
                    AnonymousPaths = [AnonymousPath],
                },
            },
        };

        _errorPageProvider = Substitute.For<IErrorPageProvider>();
        _context = new DefaultHttpContext();
        _context.Request.Path = "/";
    }

    /// <summary>
    /// Builds the middleware over the current configuration.
    /// </summary>
    /// <remarks>
    /// Deferred to the spec rather than done in <c>Establish</c>, so a spec can change the configuration
    /// first — the options monitor captures the instance it is told about.
    /// </remarks>
    protected void BuildMiddleware()
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(_config);

        _middleware = new AccessControlMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            config,
            new AccessPolicy(),
            _errorPageProvider,
            Substitute.For<ILogger<AccessControlMiddleware>>());
    }

    /// <summary>
    /// Puts an authenticated caller carrying the given claims on the request.
    /// </summary>
    /// <param name="claims">The claims the caller carries.</param>
    protected void CallerCarrying(params Claim[] claims) =>
        _context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "spec"));
}
