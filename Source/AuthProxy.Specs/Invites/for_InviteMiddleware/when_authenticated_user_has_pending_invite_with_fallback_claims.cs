// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

public class when_authenticated_user_has_pending_invite_with_fallback_claims : Specification
{
    InviteMiddleware _middleware;
    DefaultHttpContext _context;
    CapturingHttpMessageHandler _messageHandler;
    bool _nextCalled;

    void Establish()
    {
        var tokenValidator = Substitute.For<IInviteTokenValidator>();

        var config = new C.AuthProxy
        {
            Invite = new C.Invite { ExchangeUrl = "http://studio/internal/invites/exchange" }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        _messageHandler = new CapturingHttpMessageHandler();
        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(new HttpClient(_messageHandler));

        _middleware = new InviteMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            tokenValidator,
            optionsMonitor,
            CreateEmptyAuthConfig(),
            httpClientFactory,
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ILogger<InviteMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/";
        _context.User = new ClaimsPrincipal(
            new ClaimsIdentity(
                [new Claim(ClaimTypes.NameIdentifier, "user-123")],
                "aad"));
        _context.Request.Headers.Cookie = $"{Cookies.InviteToken}=pending-invite-token";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
    [Fact] void should_send_the_fallback_subject() => _messageHandler.Subject.ShouldEqual("user-123");
    [Fact] void should_send_the_authentication_type_as_identity_provider() => _messageHandler.IdentityProvider.ShouldEqual("aad");
    [Fact] void should_send_the_invite_token_as_bearer_authentication() => _messageHandler.AuthorizationParameter.ShouldEqual("pending-invite-token");

    static IOptionsMonitor<C.Authentication> CreateEmptyAuthConfig()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.Authentication>>();
        monitor.CurrentValue.Returns(new C.Authentication());
        return monitor;
    }

    class CapturingHttpMessageHandler : HttpMessageHandler
    {
        public string Subject { get; private set; } = string.Empty;
        public string IdentityProvider { get; private set; } = string.Empty;
        public string AuthorizationParameter { get; private set; } = string.Empty;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            AuthorizationParameter = request.Headers.Authorization?.Parameter ?? string.Empty;

            var payload = JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!.AsObject();
            Subject = payload["subject"]?.GetValue<string>() ?? string.Empty;
            IdentityProvider = payload["identityProvider"]?.GetValue<string>() ?? string.Empty;

            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }
}