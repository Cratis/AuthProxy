// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.Identity.for_IdentityMiddleware.given;

/// <summary>
/// Provides the middleware with an authenticated caller, a resolver that would admit them, and a deployment
/// whose one service treats its identity answer as an authorization decision.
/// </summary>
/// <remarks>
/// Everything is left mutable so a spec states only the one thing it is about: whether a tenant reached
/// <see cref="HttpContext.Items"/>, what the deployment requires, and what the path is. The resolver is a
/// substitute rather than the real one because the question here is not what a verdict is worth — that is
/// <c>for_IdentityDetailsResolver</c>'s — but whether the verdict is asked for at all.
/// </remarks>
public class an_identity_middleware : Specification
{
    /// <summary>The tenant a request carries when one resolved.</summary>
    protected const string TenantId = "tenant-a";

    /// <summary>An ordinary application path, forwarded to a service when nothing refuses it.</summary>
    protected const string ProtectedPath = "/private";

    protected C.AuthProxy _config;
    protected C.Service _service;
    protected IIdentityDetailsResolver _resolver;
    protected IErrorPageProvider _errorPages;
    protected IAuthenticationService _authenticationService;
    protected DefaultHttpContext _context;
    protected IdentityMiddleware _middleware;
    protected bool _nextCalled;

    void Establish()
    {
        _service = new C.Service
        {
            Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" },
            IdentityVerification = C.IdentityVerificationMode.Required
        };
        _config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service> { ["main"] = _service }
        };

        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(_ => _config);

        _resolver = Substitute.For<IIdentityDetailsResolver>();
        _resolver
            .Resolve(Arg.Any<HttpContext>(), Arg.Any<ClientPrincipal>(), Arg.Any<string>())
            .Returns(_ => new IdentityProviderResult("user-1", "User One", true, true, [], new object()));

        _errorPages = Substitute.For<IErrorPageProvider>();

        _context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("oid", "user-1"),
                new Claim("name", "User One")
            ],
            "aad"))
        };
        _context.Request.Path = ProtectedPath;

        _authenticationService = Substitute.For<IAuthenticationService>();
        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(_authenticationService);
        _context.RequestServices = serviceProvider;

        _middleware = new IdentityMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            options,
            _resolver,
            _errorPages);
    }

    /// <summary>
    /// Puts a resolved tenant on the request, the way <see cref="TenancyMiddleware"/> does.
    /// </summary>
    /// <param name="tenantId">The tenant to record.</param>
    protected void ResolveTenant(string tenantId = TenantId) =>
        _context.Items[TenancyMiddleware.TenantIdItemKey] = tenantId;

    /// <summary>
    /// Enables local session termination when identity verification refuses the caller.
    /// </summary>
    protected void EnableSessionTermination() => _config.Session.TerminateOnIdentityDenial = true;

    /// <summary>
    /// Asserts that the request was refused with the forbidden page.
    /// </summary>
    protected void ShouldHaveBeenRefused() =>
        _errorPages.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.Forbidden, StatusCodes.Status403Forbidden);

    /// <summary>
    /// Asserts that the local authentication session was terminated.
    /// </summary>
    protected void ShouldHaveTerminatedSession() =>
        _authenticationService.Received(1).SignOutAsync(
            _context,
            CookieAuthenticationDefaults.AuthenticationScheme,
            Arg.Any<AuthenticationProperties?>());

    /// <summary>
    /// Asserts that the local authentication session was preserved.
    /// </summary>
    protected void ShouldHavePreservedSession() =>
        _authenticationService.DidNotReceive().SignOutAsync(
            Arg.Any<HttpContext>(),
            Arg.Any<string>(),
            Arg.Any<AuthenticationProperties?>());
}
