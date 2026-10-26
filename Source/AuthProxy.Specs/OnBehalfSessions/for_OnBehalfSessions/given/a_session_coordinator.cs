// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.given;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;

public class a_session_coordinator : Specification
{
    protected OnBehalfConfiguration _configuration;
    protected ManualTime _time;
    protected OnBehalfSessionLedger _ledger;
    protected OnBehalfSessionProtector _protector;
    protected IOnBehalfGrants _grants;
    protected IOnBehalfSessionNotifier _notifier;
    protected OnBehalfSessions _sessions;
    protected DefaultHttpContext _context;
    protected DateTimeOffset _start;

    void Establish()
    {
        _start = new DateTimeOffset(2026, 9, 1, 12, 0, 0, TimeSpan.Zero);
        _configuration = new();
        _time = new(_start);
        _ledger = new(_time);
        _protector = new(new EphemeralDataProtectionProvider());
        _grants = Substitute.For<IOnBehalfGrants>();
        _grants.Check(Arg.Any<OnBehalfSession>(), Arg.Any<ClientPrincipal>(), Arg.Any<CancellationToken>())
            .Returns(OnBehalfGrant.Live(_start.AddHours(2), Sessions.Represented()));
        _notifier = Substitute.For<IOnBehalfSessionNotifier>();
        _notifier.Started(Arg.Any<OnBehalfSession>(), Arg.Any<OnBehalfGrant>(), Arg.Any<CancellationToken>()).Returns(true);
        _notifier.Ended(Arg.Any<OnBehalfSession>(), Arg.Any<OnBehalfSessionEndReason>(), Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>()).Returns(true);

        _sessions = new(
            _configuration.Monitor,
            new OnBehalfSessionCookie(_protector),
            _grants,
            _notifier,
            new OnBehalfAttestations(_configuration.Monitor, _time),
            _ledger,
            Substitute.For<ILogger<OnBehalfSessions>>());

        _context = new DefaultHttpContext { User = Sessions.ActorPrincipal() };
    }

    protected string SetCookie => _context.Response.Headers.SetCookie.ToString();

    protected void Carry(OnBehalfSession session) =>
        _context.Request.Headers.Cookie = $"{Cookies.OnBehalf}={_protector.Protect(session)}";
}
