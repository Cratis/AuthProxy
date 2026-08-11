// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

/// <summary>
/// Reusable context that drives <see cref="InviteMiddleware"/> through Phase 1 — the invitation link itself
/// arriving on <c>/invite/{token}</c> — with identity providers configured, so a specification can say what
/// the caller is offered before any provider handshake has happened.
/// </summary>
public class an_invitation_entry : Specification
{
    protected const string Capability = "some-token";

    protected InviteMiddleware _middleware;
    protected DefaultHttpContext _context;
    protected IErrorPageProvider _errorPageProvider;
    protected IAuthenticationService _authenticationService;
    protected bool _nextCalled;

    /// <summary>
    /// Gets the identity providers the deployment has configured.
    /// </summary>
    protected virtual IReadOnlyList<C.OidcProvider> Providers =>
    [
        new() { Name = "GitHub", Authority = "https://github.test", ClientId = "github-id", ClientSecret = "github-secret" },
        new() { Name = "Google", Authority = "https://accounts.google.com", ClientId = "google-id", ClientSecret = "google-secret" }
    ];

    void Establish()
    {
        var tokenValidator = Substitute.For<IInviteTokenValidator>();
        tokenValidator.ValidateDetailed(Arg.Any<string>()).Returns(InviteTokenValidationResult.Valid);

        var config = new C.AuthProxy
        {
            Invite = new C.Invite { ExchangeUrl = "http://studio/internal/invites/exchange" }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        var authConfigMonitor = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfigMonitor.CurrentValue.Returns(new C.Authentication { OidcProviders = [.. Providers] });

        _errorPageProvider = Substitute.For<IErrorPageProvider>();

        _middleware = new InviteMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            tokenValidator,
            optionsMonitor,
            authConfigMonitor,
            Substitute.For<ITenantResolver>(),
            Substitute.For<IHttpClientFactory>(),
            _errorPageProvider,
            Substitute.For<ILogger<InviteMiddleware>>());

        _authenticationService = Substitute.For<IAuthenticationService>();
        _authenticationService
            .ChallengeAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<AuthenticationProperties>())
            .Returns(Task.CompletedTask);
        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(_authenticationService);

        _context = new DefaultHttpContext { RequestServices = serviceProvider };
        _context.Request.Path = $"{WellKnownPaths.InvitePathPrefix}/{Capability}";
    }

    /// <summary>
    /// Signs the caller in the way the browser already was when the invitation link was opened — a real
    /// session, established earlier and for something else, carrying no invitation binding.
    /// </summary>
    protected void GivenAPreExistingSession()
    {
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "134365")], "github"));
        InvitationSessionFixture.GivenSessionEstablishedBeforeTheInvitation(_context);
    }
}
