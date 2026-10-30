// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text.Json;
using Cratis.AuthProxy.given;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

/// <summary>
/// Drives <see cref="InviteMiddleware"/> through the staging of an attested, identity-bound invitation with a
/// recording stage endpoint, entry-state protector, authentication service and logger.
/// </summary>
public class an_attested_invitation_staging : Specification
{
    protected const string StageUrl = "https://lobby.example.com/_invite/stage";
    protected const string TenantId = "hive-consulting";
    protected const string InvitationId = "invite-42";

    protected DefaultHttpContext _context;
    protected RecordingHandler _handler;
    protected RecordingProtector _protector;
    protected IAuthenticationService _authenticationService;
    protected IErrorPageProvider _errorPages;
    protected IOptionsMonitor<C.AuthProxy> _configurationMonitor;
    protected IOptionsMonitor<C.Authentication> _authentication;
    protected IHttpClientFactory _httpClientFactory;
    protected IInviteTokenValidator _tokenValidator;
    protected StageIssuer _issuer;
    protected RecordingLogger<InviteMiddleware> _logger;
    protected bool _nextCalled;
    protected string _token;

    protected RequestDelegate Next => _ =>
    {
        _nextCalled = true;
        return Task.CompletedTask;
    };

    void Establish()
    {
        var (signingKey, publicKeyPem) = TokenFixture.GenerateKeyPair();
        _token = TokenFixture.CreateToken(
            signingKey,
            "invite-authority",
            "authproxy",
            additionalClaims:
            [
                new Claim(JwtRegisteredClaimNames.Jti, InvitationId),
                new Claim(InvitationAttestationClaims.TenantId, TenantId),
                new Claim(InvitationCapabilityClaims.RecipientProviderKey, "microsoft"),
                new Claim(InvitationCapabilityClaims.RecipientIdentityBinding, new string('A', 43)),
            ]);

        var configuration = new C.AuthProxy
        {
            Invite = new C.Invite
            {
                PublicKeyPem = publicKeyPem,
                Issuer = "invite-authority",
                Audience = "authproxy",
                StageUrl = StageUrl,
                ExchangeUrl = "https://lobby.example.com/_invite/exchange",
                TenantClaim = InvitationAttestationClaims.TenantId,
                EmailClaim = InvitationAttestationClaims.Email,
                Attestation = new C.InvitationAttestation(),
            }
        };
        _configurationMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        _configurationMonitor.CurrentValue.Returns(configuration);
        _authentication = Substitute.For<IOptionsMonitor<C.Authentication>>();
        _authentication.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders =
            [
                new C.OidcProvider
                {
                    Name = "First",
                    CanonicalIdentity = new C.CanonicalIdentity
                    {
                        ProviderKey = "microsoft",
                        InvitationIdentityBindingCompletionEnabled = true,
                    }
                },
                new C.OidcProvider
                {
                    Name = "Second",
                    CanonicalIdentity = new C.CanonicalIdentity
                    {
                        ProviderKey = "google",
                        InvitationIdentityBindingCompletionEnabled = true,
                    }
                },
            ]
        });

        _handler = new();
        _httpClientFactory = Substitute.For<IHttpClientFactory>();
        _httpClientFactory.CreateClient(Arg.Any<string>()).Returns(new HttpClient(_handler));
        _protector = new();
        _issuer = new();
        _logger = new();
        _tokenValidator = new InviteTokenValidator(_configurationMonitor, Substitute.For<IInvitationTokenKeys>());
        _errorPages = Substitute.For<IErrorPageProvider>();
        _errorPages.WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>()).Returns(Task.CompletedTask);

        var middleware = new InviteMiddleware(
            Next,
            _tokenValidator,
            _configurationMonitor,
            _authentication,
            Substitute.For<ITenantResolver>(),
            _httpClientFactory,
            _errorPages,
            _logger,
            null,
            _issuer,
            _protector);

        _context = new DefaultHttpContext();
        _context.Request.Path = $"/invite/{_token}";
        _authenticationService = Substitute.For<IAuthenticationService>();
        _authenticationService.ChallengeAsync(
                Arg.Any<HttpContext>(),
                Arg.Any<string>(),
                Arg.Any<AuthenticationProperties?>())
            .Returns(Task.CompletedTask);
        _context.RequestServices = new ServiceCollection()
            .AddSingleton(_authenticationService)
            .BuildServiceProvider();
        _context.Items["middleware"] = middleware;
    }

    protected string BodyProperty(string name)
    {
        using var document = JsonDocument.Parse(_handler.Body);
        return document.RootElement.GetProperty(name).GetString()!;
    }

    protected sealed class StageIssuer : IInvitationAttestationIssuer
    {
        public bool TryIssueStage(InvitationEntryState state, out string attestation)
        {
            attestation = "stage-attestation";
            return true;
        }

        public bool TryIssueComplete(InvitationEntryState state, InvitationVerifiedIdentity identity, out string attestation)
        {
            attestation = string.Empty;
            return false;
        }
    }

    protected sealed class RecordingProtector : IInvitationEntryStateProtector
    {
        public InvitationEntryState? State { get; private set; }

        public string Protect(InvitationEntryState state)
        {
            State = state;
            return "protected-state";
        }

        public bool TryUnprotect(string protectedState, out InvitationEntryState state)
        {
            state = default!;
            return false;
        }
    }

    protected sealed class RecordingHandler : HttpMessageHandler
    {
        public HttpStatusCode StatusCode { get; set; } = HttpStatusCode.OK;

        public HttpRequestMessage? Request { get; private set; }

        public string Body { get; private set; } = string.Empty;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Request = request;
            Body = await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(StatusCode);
        }
    }
}
