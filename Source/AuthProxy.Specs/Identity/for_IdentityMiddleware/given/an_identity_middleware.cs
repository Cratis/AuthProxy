// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;
using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.given;
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
/// <c language="text">for_IdentityDetailsResolver</c>'s — but whether the verdict is asked for at all.
/// </remarks>
public class an_identity_middleware : Specification
{
    /// <summary>The tenant a request carries when one resolved.</summary>
    protected const string TenantId = "tenant-a";

    /// <summary>An ordinary application path, forwarded to a service when nothing refuses it.</summary>
    protected const string ProtectedPath = "/private";

    protected C.AuthProxy _config;
    protected C.Authentication _authentication;
    protected C.Service _service;
    protected IIdentityDetailsResolver _resolver;
    protected IErrorPageProvider _errorPages;
    protected IAuthenticationService _authenticationService;
    protected DefaultHttpContext _context;
    protected IdentityMiddleware _middleware;
    protected RecordingLogger<IdentityMiddleware> _logger;
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
        _authentication = new C.Authentication();

        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(_ => _config);
        var authenticationOptions = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authenticationOptions.CurrentValue.Returns(_ => _authentication);

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

        _logger = new RecordingLogger<IdentityMiddleware>();
        _middleware = new IdentityMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            options,
            authenticationOptions,
            _resolver,
            _errorPages,
            _logger);
    }

    /// <summary>
    /// Puts a resolved tenant on the request, the way <see cref="TenancyMiddleware"/> does.
    /// </summary>
    /// <param name="tenantId">The tenant to record.</param>
    protected void ResolveTenant(string tenantId = TenantId) =>
        _context.Items[TenancyMiddleware.TenantIdItemKey] = tenantId;

    /// <summary>
    /// Registers an OIDC provider and makes the caller's session record it as the provider they signed in through.
    /// </summary>
    /// <param name="denialResponse">How the provider answers an identity denial.</param>
    protected void SignedInThroughProvider(C.OidcDenialResponse denialResponse)
    {
        _authentication.OidcProviders = [new C.OidcProvider { Name = "Microsoft", DenialResponse = denialResponse }];
        var scheme = OidcProviderScheme.FromName("Microsoft");
        var identity = new ClaimsIdentity(_context.User.Claims.Append(new Claim(SessionClaims.ProviderScheme, scheme)), "aad");
        _context.User = new ClaimsPrincipal(identity);
        var properties = new AuthenticationProperties();
        properties.Items[SessionProvider.MarkerStateKey] = scheme;
        _context.Features.Set<IAuthenticateResultFeature>(
            new EstablishedSession(AuthenticateResult.Success(new AuthenticationTicket(_context.User, properties, CookieAuthenticationDefaults.AuthenticationScheme))));
    }

    /// <summary>
    /// Makes the request look like a browser navigating to a page.
    /// </summary>
    protected void Navigate() => _context.Request.Headers["Sec-Fetch-Dest"] = "document";

    /// <summary>
    /// Denies the caller's identity the way a service's identity details do.
    /// </summary>
    protected void DenyIdentity() =>
        _resolver
            .Resolve(Arg.Any<HttpContext>(), Arg.Any<ClientPrincipal>(), Arg.Any<string>())
            .Returns(_ => new IdentityProviderResult("user-1", "User One", true, false, [], new object()));

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

    sealed class EstablishedSession(AuthenticateResult result) : IAuthenticateResultFeature
    {
        public AuthenticateResult? AuthenticateResult { get; set; } = result;
    }
}
