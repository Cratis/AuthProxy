// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackMiddleware.given;

/// <summary>
/// Provides the middleware in front of one service, with a browser session on the request and a dispatcher that
/// records what it is asked to report.
/// </summary>
public class a_callback_middleware : Specification
{
    protected C.Service _service;
    protected C.AuthProxy _config;
    protected ISignInCallbackDispatcher _dispatcher;
    protected SignInCallbackMiddleware _middleware;
    protected DefaultHttpContext _context;
    protected bool _nextCalled;

    protected virtual C.SignInCallback? Callback => new() { Path = "/.cratis/showrunner/sign-in" };

    protected virtual string Scheme => CookieAuthenticationDefaults.AuthenticationScheme;

    protected virtual bool Authenticated => true;

    void Establish()
    {
        _service = new C.Service
        {
            Backend = new C.ServiceEndpoint { BaseUrl = "http://app.internal:8080" },
            SignInCallback = Callback
        };
        _config = new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["app"] = _service } };
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(_ => _config);

        _dispatcher = Substitute.For<ISignInCallbackDispatcher>();
        _context = new DefaultHttpContext();
        _context.Request.Path = "/dashboard";
        _context.Items[TenancyMiddleware.TenantIdItemKey] = "tenant-a";

        if (Authenticated)
        {
            var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-1"), new Claim("name", "User One")], "github"));
            _context.User = principal;
            _context.Features.Set<IAuthenticateResultFeature>(new ResultFeature(
                AuthenticateResult.Success(new AuthenticationTicket(principal, new AuthenticationProperties(), Scheme))));
        }

        _middleware = new SignInCallbackMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            options,
            _dispatcher);
    }

    sealed class ResultFeature(AuthenticateResult result) : IAuthenticateResultFeature
    {
        public AuthenticateResult? AuthenticateResult { get; set; } = result;
    }
}
