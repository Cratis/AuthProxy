// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Ingress;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

public class a_sign_in_notifier : Specification
{
    protected const string NotifyUrl = "https://studio.example.com/api/internal/sign-ins";
    protected const string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    /// <summary>The address the forwarded-headers middleware left on the connection.</summary>
    protected const string ConnectionAddress = "198.51.100.5";

    /// <summary>An address written into a raw forwarded header, which nothing is entitled to read.</summary>
    protected const string ForgedForwardedAddress = "203.0.113.7";

    protected SignInNotifier _notifier;
    protected RecordingHttpMessageHandler _handler;
    protected IOptionsMonitor<C.AuthProxy> _config;
    protected ClaimsPrincipal _principal;
    protected DefaultHttpContext _httpContext;

    protected virtual C.AuthProxy CreateConfig() => new() { SignIn = new C.SignIn { NotifyUrl = NotifyUrl } };

    protected virtual HttpStatusCode NotifyStatusCode => HttpStatusCode.OK;

    protected virtual ClaimsPrincipal CreatePrincipal() => new(new ClaimsIdentity(
    [
        new Claim("sub", "subject-123"),
        new Claim("iss", "https://github.com"),
    ],
    "github"));

    protected virtual SignInNotifier CreateNotifier(
        C.AuthProxy configuration,
        IOptionsMonitor<C.AuthProxy> optionsMonitor,
        IHttpClientFactory httpClientFactory) =>
        new(
            optionsMonitor,
            new ClientLocationResolver(),
            httpClientFactory,
            Substitute.For<ILogger<SignInNotifier>>());

    void Establish()
    {
        var configuration = CreateConfig();
        _config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        _config.CurrentValue.Returns(configuration);

        _handler = new RecordingHttpMessageHandler(NotifyStatusCode);
        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(_handler));

        _principal = CreatePrincipal();

        // A request as it looks after the ingress pipeline has run: the connection carries the address the
        // forwarded-headers middleware settled on, and the raw forwarded header is still on the request
        // carrying a different, attacker-chosen address. A notification that reported that one instead would
        // record an address nothing else in the proxy ever used, which is what this deliberately pins.
        _httpContext = new DefaultHttpContext();
        _httpContext.Connection.RemoteIpAddress = IPAddress.Parse(ConnectionAddress);
        _httpContext.MarkTrustedProxyPeer(true);
        _httpContext.Request.Headers.UserAgent = UserAgent;
        _httpContext.Request.Headers["X-Forwarded-For"] = $"{ForgedForwardedAddress}, 10.0.0.1";
        _httpContext.Request.Headers["X-Geo-City"] = "Oslo";
        _httpContext.Request.Headers["X-Geo-Country"] = "NO";

        _notifier = CreateNotifier(configuration, _config, httpClientFactory);
    }
}
