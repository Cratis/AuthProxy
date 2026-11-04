// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.given;
using Cratis.AuthProxy.SignInCallbacks.given;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackDispatcher.given;

/// <summary>
/// Provides a dispatcher for one service that has a sign-in callback, a queue that records what it is given and a clock
/// that only moves when told to.
/// </summary>
public class a_dispatcher : Specification
{
    protected const string ServiceName = "app";
    protected const string CallbackPath = "/.cratis/showrunner/sign-in";
    protected const string Tenant = "tenant-a";

    protected C.AuthProxy _config;
    protected C.Service _service;
    protected RecordingCallbackQueue _queue;
    protected ManualTimeProvider _time;
    protected ITenantResolver _tenants;
    protected SignInCallbackDispatcher _dispatcher;
    protected DefaultHttpContext _context;
    protected ClaimsPrincipal _user;
    protected ClientPrincipal _principal;

    /// <summary>
    /// Gets the callback the service declares; <see langword="null"/> leaves the feature off.
    /// </summary>
    protected virtual C.SignInCallback? Callback => new() { Path = CallbackPath };

    protected ClientPrincipal PrincipalFor(string subject) => new()
    {
        IdentityProvider = "github",
        UserId = subject,
        UserDetails = "User",
    };

    protected void SignIn(string subject = "user-1") =>
        _dispatcher.SignedIn(
            _context,
            new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("sub", subject),
                new Claim("name", "User One"),
                new Claim("email", "user.one@example.com")
            ],
            "github")),
            "github",
            new AuthenticationProperties());

    protected void Return(string subject = "user-1") =>
        _dispatcher.Returned(_context, ServiceName, _service, PrincipalFor(subject), Tenant);

    void Establish()
    {
        _service = new C.Service
        {
            Backend = new C.ServiceEndpoint { BaseUrl = "http://app.internal:8080/" },
            SignInCallback = Callback
        };
        _config = new C.AuthProxy { Services = new Dictionary<string, C.Service> { [ServiceName] = _service } };

        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(_ => _config);

        _queue = new RecordingCallbackQueue();
        _time = new ManualTimeProvider();
        _tenants = Substitute.For<ITenantResolver>();
        _tenants.TryResolve(Arg.Any<HttpContext>(), out Arg.Any<string>()).Returns(call =>
        {
            call[1] = Tenant;
            return true;
        });

        _context = new DefaultHttpContext();
        _principal = PrincipalFor("user-1");
        var services = new ServiceCollection().AddSingleton(_tenants).BuildServiceProvider();
        _dispatcher = new SignInCallbackDispatcher(options, _queue, services, _time, new RecordingLogger<SignInCallbackDispatcher>());
    }
}
