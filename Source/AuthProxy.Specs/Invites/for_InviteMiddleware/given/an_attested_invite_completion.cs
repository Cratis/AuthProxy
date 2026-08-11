// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Security.Cryptography;
using System.Text;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

public class an_attested_invite_completion : Specification
{
    protected const string ExchangeUrl = "https://lobby.example.com/_invite/exchange";
    protected const string InviteIssuer = "invite-authority";
    protected const string InviteAudience = "authproxy";
    protected const string TenantId = "hive-consulting";
    protected const string InvitationId = "invite-42";
    protected const string Transaction = "transaction-value";
    protected const string Challenge = "challenge-value";
    protected const string CapabilityHash = "capability-hash";
    protected const string Email = "invitee@example.com";

    protected DefaultHttpContext _context;
    protected InviteMiddleware _middleware;
    protected RecordingAttestationIssuer _attestationIssuer;
    protected RecordingHandler _handler;
    protected IErrorPageProvider _errorPageProvider;
    protected bool _nextCalled;

    protected virtual bool InvitationCompletionEnabled => true;
    protected virtual bool InvitationIdentityBindingCompletionEnabled => false;
    protected virtual bool IncludeVerifiedEmailClaims => true;
    protected virtual IReadOnlyList<Claim> InvitationClaims => [new(InvitationAttestationClaims.Email, Email)];

    void Establish()
    {
        var (inviteSigningKey, publicKeyPem) = TokenFixture.GenerateKeyPair();
        var inviteConfig = new C.AuthProxy
        {
            Invite = new C.Invite
            {
                PublicKeyPem = publicKeyPem,
                Issuer = InviteIssuer,
                Audience = InviteAudience,
                TenantClaim = InvitationAttestationClaims.TenantId,
                EmailClaim = InvitationAttestationClaims.Email,
                ExchangeUrl = ExchangeUrl,
                StageUrl = "https://lobby.example.com/_invite/stage",
                Attestation = new C.InvitationAttestation(),
            }
        };
        var inviteOptions = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        inviteOptions.CurrentValue.Returns(inviteConfig);

        var authentication = new C.Authentication
        {
            OAuthProviders =
            [
                new C.OAuthProvider
                {
                    Name = "Workforce",
                    CanonicalIdentity = new C.CanonicalIdentity
                    {
                        InvitationCompletionEnabled = InvitationCompletionEnabled,
                        InvitationIdentityBindingCompletionEnabled = InvitationIdentityBindingCompletionEnabled,
                        ProviderKey = "workforce",
                        SubjectClaimType = "provider_sub",
                        Issuer = "https://identity.example.com",
                    }
                }
            ]
        };
        var authenticationOptions = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authenticationOptions.CurrentValue.Returns(authentication);

        var claims = new List<Claim>
        {
            new(CanonicalIdentityClaims.ProviderKey, "workforce"),
            new(CanonicalIdentityClaims.Issuer, "https://identity.example.com"),
            new(CanonicalIdentityClaims.Subject, "provider-subject"),
            new("acr", "mfa"),
        };
        if (IncludeVerifiedEmailClaims)
        {
            claims.Add(new Claim("email", Email));
            claims.Add(new Claim("email_verified", bool.TrueString.ToLowerInvariant()));
        }

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));
        var properties = new AuthenticationProperties
        {
            IssuedUtc = new DateTimeOffset(2026, 8, 10, 1, 2, 3, TimeSpan.Zero),
        };
        properties.Items[InvitationAuthenticationState.TransactionStateKey] = Transaction;
        properties.Items[InvitationAuthenticationState.ChallengeStateKey] = Challenge;
        properties.Items[InvitationAuthenticationState.CapabilityHashStateKey] = CapabilityHash;

        var authenticationService = Substitute.For<IAuthenticationService>();
        authenticationService.AuthenticateAsync(Arg.Any<HttpContext>(), CookieAuthenticationDefaults.AuthenticationScheme)
            .Returns(AuthenticateResult.Success(new AuthenticationTicket(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme)));

        _context = new DefaultHttpContext
        {
            User = principal,
            RequestServices = new ServiceCollection()
                .AddSingleton<IAuthenticationService>(authenticationService)
                .BuildServiceProvider(),
        };
        _context.Request.Path = "/";

        var token = TokenFixture.CreateToken(
            inviteSigningKey,
            InviteIssuer,
            InviteAudience,
            additionalClaims:
            [
                new Claim(JwtRegisteredClaimNames.Jti, InvitationId),
                new Claim(InvitationAttestationClaims.TenantId, TenantId),
                .. InvitationClaims,
            ]);
        properties.Items[InvitationAuthenticationState.CapabilityHashStateKey] = ComputeHash(token);
        _context.Request.Headers.Cookie = $"{Cookies.InviteToken}={token}; {Cookies.InvitationEntryState}=protected-state";
        InvitationSessionFixture.GivenSessionEstablishedByTheInvitation(_context, token);

        var protector = Substitute.For<IInvitationEntryStateProtector>();
        protector.TryUnprotect("protected-state", out Arg.Any<InvitationEntryState>())
            .Returns(callInfo =>
            {
                callInfo[1] = new InvitationEntryState(
                    TenantId,
                    InvitationId,
                    Transaction,
                    Challenge,
                    ComputeHash(token),
                    DateTimeOffset.UtcNow.AddMinutes(10));
                return true;
            });

        _attestationIssuer = new();
        _handler = new();
        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(new HttpClient(_handler));
        _errorPageProvider = Substitute.For<IErrorPageProvider>();
        _errorPageProvider.WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>()).Returns(Task.CompletedTask);

        _middleware = new(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            new InviteTokenValidator(inviteOptions),
            inviteOptions,
            authenticationOptions,
            Substitute.For<ITenantResolver>(),
            httpClientFactory,
            _errorPageProvider,
            Substitute.For<ILogger<InviteMiddleware>>(),
            new CanonicalIdentityResolver(authenticationOptions),
            _attestationIssuer,
            protector);
    }

    protected static string ComputeHash(string token) =>
        Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    protected sealed class RecordingAttestationIssuer : IInvitationAttestationIssuer
    {
        public InvitationVerifiedIdentity? Identity { get; private set; }

        public bool TryIssueStage(InvitationEntryState state, out string attestation)
        {
            attestation = "stage-attestation";
            return true;
        }

        public bool TryIssueComplete(InvitationEntryState state, InvitationVerifiedIdentity identity, out string attestation)
        {
            Identity = identity;
            attestation = "complete-attestation";
            return true;
        }
    }

    protected sealed class RecordingHandler : HttpMessageHandler
    {
        public HttpRequestMessage? Request { get; private set; }

        public string Body { get; private set; } = string.Empty;

        public HttpStatusCode StatusCode { get; set; } = HttpStatusCode.OK;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Request = request;
            Body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(StatusCode);
        }
    }
}
