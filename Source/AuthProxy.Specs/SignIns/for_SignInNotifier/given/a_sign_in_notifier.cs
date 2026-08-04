// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

public class a_sign_in_notifier : Specification
{
    protected const string NotifyUrl = "https://studio.example.com/api/internal/sign-ins";
    protected const string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

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

    void Establish()
    {
        _config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        _config.CurrentValue.Returns(CreateConfig());

        _handler = new RecordingHttpMessageHandler(NotifyStatusCode);
        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(_handler));

        _principal = CreatePrincipal();

        _httpContext = new DefaultHttpContext();
        _httpContext.Request.Headers.UserAgent = UserAgent;
        _httpContext.Request.Headers["X-Forwarded-For"] = "203.0.113.7, 10.0.0.1";
        _httpContext.Request.Headers["X-Geo-City"] = "Oslo";
        _httpContext.Request.Headers["X-Geo-Country"] = "NO";

        _notifier = new SignInNotifier(
            _config,
            new ClientLocationResolver(),
            httpClientFactory,
            Substitute.For<ILogger<SignInNotifier>>());
    }
}
