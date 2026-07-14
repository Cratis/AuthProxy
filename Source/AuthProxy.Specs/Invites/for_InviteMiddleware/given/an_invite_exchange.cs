// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

/// <summary>
/// Reusable context that drives <see cref="InviteMiddleware"/> through its Phase-2 (post-login)
/// invite exchange using a <em>real</em> <see cref="InviteTokenValidator"/> and a signed invite token,
/// so re-validation and email binding are actually exercised. Concrete specs set the pending invite
/// cookie and the authenticated user in their own <c>Establish</c>, then invoke the middleware.
/// </summary>
public class an_invite_exchange : Specification
{
    protected const string ExchangeUrl = "http://studio/internal/invites/exchange";
    protected const string Issuer = "test-issuer";
    protected const string Audience = "test-audience";

    protected RsaSecurityKey _signingKey;
    protected InviteMiddleware _middleware;
    protected DefaultHttpContext _context;
    protected IErrorPageProvider _errorPageProvider;
    protected bool _nextCalled;
    protected bool _exchangeCalled;
    protected string _exchangeRequestBody = string.Empty;

    void Establish()
    {
        var (privateKey, publicKeyPem) = TokenFixture.GenerateKeyPair();
        _signingKey = privateKey;

        var config = new C.AuthProxy
        {
            Invite = new C.Invite
            {
                PublicKeyPem = publicKeyPem,
                Issuer = Issuer,
                Audience = Audience,
                ExchangeUrl = ExchangeUrl,
            }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new CapturingHandler(this)));

        _errorPageProvider = Substitute.For<IErrorPageProvider>();
        _errorPageProvider
            .WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>())
            .Returns(Task.CompletedTask);

        _middleware = new InviteMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            new InviteTokenValidator(optionsMonitor),
            optionsMonitor,
            EmptyAuthConfig(),
            Substitute.For<ITenantResolver>(),
            httpClientFactory,
            _errorPageProvider,
            Substitute.For<ILogger<InviteMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/";
    }

    /// <summary>
    /// Creates a signed invite token, overriding the signing key or standard claims when a test
    /// needs to forge, expire, or otherwise diverge from a valid token.
    /// </summary>
    /// <param name="signingKey">The key to sign with; defaults to the configured (trusted) key.</param>
    /// <param name="issuer">The <c>iss</c> claim; defaults to the expected issuer.</param>
    /// <param name="audience">The <c>aud</c> claim; defaults to the expected audience.</param>
    /// <param name="expires">The expiry time; defaults to one hour from now.</param>
    /// <param name="notBefore">The earliest valid time; defaults to one minute ago.</param>
    /// <param name="claims">Additional claims to embed in the token.</param>
    /// <returns>The compact-serialized signed JWT.</returns>
    protected string CreateSignedToken(
        RsaSecurityKey? signingKey = null,
        string issuer = Issuer,
        string audience = Audience,
        DateTime? expires = null,
        DateTime? notBefore = null,
        IEnumerable<Claim>? claims = null) =>
        TokenFixture.CreateToken(signingKey ?? _signingKey, issuer, audience, expires, notBefore, claims);

    /// <summary>
    /// Marks the request as authenticated, always carrying a <c>sub</c> claim plus any supplied claims.
    /// </summary>
    /// <param name="claims">Additional claims (e.g. <c>email</c>, <c>email_verified</c>) for the account.</param>
    protected void GivenAuthenticatedUserWith(params Claim[] claims) =>
        _context.User = new ClaimsPrincipal(new ClaimsIdentity(claims.Prepend(new Claim("sub", "user-123")), "aad"));

    /// <summary>
    /// Places the given token in the pending invite cookie, as it would arrive on the Phase-2 request.
    /// </summary>
    /// <param name="token">The token to carry in the <c>.cratis-invite</c> cookie.</param>
    protected void GivenPendingInviteCookie(string token) =>
        _context.Request.Headers.Cookie = $"{Cookies.InviteToken}={token}";

    static IOptionsMonitor<C.Authentication> EmptyAuthConfig()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.Authentication>>();
        monitor.CurrentValue.Returns(new C.Authentication());
        return monitor;
    }

    sealed class CapturingHandler(an_invite_exchange owner) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            owner._exchangeCalled = true;
            if (request.Content is not null)
            {
                owner._exchangeRequestBody = await request.Content.ReadAsStringAsync(cancellationToken);
            }

            return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        }
    }
}
