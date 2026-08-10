// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.given;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

/// <summary>
/// Drives <see cref="InviteMiddleware"/> with an enabled logger that records every formatted message, so a
/// specification can read exactly what a log sink would have received.
/// </summary>
/// <remarks>
/// The invite exchange endpoint is answered from here rather than from the inherited capturing handler, so a
/// specification can pick the outcome it needs — a status, or a call that never produces a response at all —
/// and reach the log statement that outcome writes.
/// </remarks>
public class an_invite_exchange_with_recorded_logs : an_invite_exchange
{
    /// <summary>
    /// The sentinel standing in for a live bearer capability. It is planted where a real capability travels —
    /// the invitation path and the pending-invitation cookie — and asserted absent from every recorded message.
    /// </summary>
    protected const string SensitiveCapability = "sensitive-capability-value";

    /// <summary>
    /// The sentinel standing in for the raw provider-supplied subject of a legacy authenticated session.
    /// </summary>
    protected const string SensitiveSubject = "sensitive-provider-subject";

    protected readonly RecordingLogger<InviteMiddleware> _logger = new();

    /// <summary>
    /// Gets the status the invite exchange endpoint answers with.
    /// </summary>
    protected virtual HttpStatusCode ExchangeStatusCode => HttpStatusCode.OK;

    /// <summary>
    /// Gets a value indicating whether the exchange call fails before it produces any response.
    /// </summary>
    protected virtual bool ExchangeCallThrows => false;

    /// <summary>
    /// Puts an invitation request carrying the given capability on the request path, exactly as a Phase-1
    /// invitation link arrives.
    /// </summary>
    /// <param name="capability">The capability carried in the path.</param>
    protected void GivenInvitationRequestFor(string capability) =>
        _context.Request.Path = $"{WellKnownPaths.InvitePathPrefix}/{capability}";

    /// <summary>
    /// Marks the request as authenticated by a legacy provider account whose subject is the sentinel.
    /// </summary>
    /// <param name="claims">Additional claims (e.g. <c>email</c>, <c>email_verified</c>) for the account.</param>
    protected void GivenLegacyAuthenticatedUserWith(params Claim[] claims) =>
        _context.User = new ClaimsPrincipal(new ClaimsIdentity(claims.Prepend(new Claim("sub", SensitiveSubject)), "aad"));

    protected override InviteMiddleware CreateMiddleware(
        C.AuthProxy configuration,
        IOptionsMonitor<C.AuthProxy> optionsMonitor,
        IHttpClientFactory httpClientFactory)
    {
        var clients = Substitute.For<IHttpClientFactory>();
        clients.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new ExchangeHandler(this)));

        var authenticationConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authenticationConfig.CurrentValue.Returns(new C.Authentication());

        return new InviteMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            new InviteTokenValidator(optionsMonitor),
            optionsMonitor,
            authenticationConfig,
            Substitute.For<ITenantResolver>(),
            clients,
            _errorPageProvider,
            _logger);
    }

    sealed class ExchangeHandler(an_invite_exchange_with_recorded_logs owner) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            owner._exchangeCalled = true;

            return owner.ExchangeCallThrows
                ? throw new HttpRequestException("Simulated exchange failure")
                : Task.FromResult(new HttpResponseMessage(owner.ExchangeStatusCode));
        }
    }
}
