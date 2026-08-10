// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

public class when_staging_an_attested_invitation : Specification
{
    const string StageUrl = "https://lobby.example.com/_invite/stage";
    const string TenantId = "hive-consulting";
    const string InvitationId = "invite-42";
    DefaultHttpContext _context;
    RecordingHandler _handler;
    RecordingProtector _protector;
    IAuthenticationService _authenticationService;
    bool _nextCalled;
    string _token;

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
        var configurationMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        configurationMonitor.CurrentValue.Returns(configuration);
        var authentication = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authentication.CurrentValue.Returns(new C.Authentication
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
        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(new HttpClient(_handler));
        _protector = new();
        var errorPages = Substitute.For<IErrorPageProvider>();
        errorPages.WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>()).Returns(Task.CompletedTask);

        var middleware = new InviteMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            new InviteTokenValidator(configurationMonitor),
            configurationMonitor,
            authentication,
            Substitute.For<ITenantResolver>(),
            httpClientFactory,
            errorPages,
            Substitute.For<ILogger<InviteMiddleware>>(),
            null,
            new StageIssuer(),
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

    async Task Because() => await ((InviteMiddleware)_context.Items["middleware"]!).InvokeAsync(_context);

    [Fact] void should_authenticate_the_stage_call() => _handler.Request!.Headers.Authorization!.Parameter.ShouldEqual("stage-attestation");
    [Fact] void should_send_the_exact_invitation_capability() => BodyProperty("invitationToken").ShouldEqual(_token);
    [Fact] void should_send_the_authproxy_transaction() => BodyProperty("invitationTransaction").ShouldEqual(_protector.State!.InvitationTransaction);
    [Fact] void should_send_the_independent_challenge() => BodyProperty("invitationChallenge").ShouldEqual(_protector.State!.InvitationChallenge);
    [Fact] void should_not_send_identity_authority() => _handler.Body.ShouldNotContain("provider");
    [Fact] void should_protect_the_staged_state_for_the_provider_round_trip() => _protector.State.ShouldNotBeNull();
    [Fact] void should_allow_only_the_provider_named_by_the_signed_capability() => _authenticationService.Received(1).ChallengeAsync(_context, OidcProviderScheme.FromName("First"), Arg.Any<AuthenticationProperties?>());
    [Fact] void should_not_offer_another_provider() => _authenticationService.DidNotReceive().ChallengeAsync(_context, OidcProviderScheme.FromName("Second"), Arg.Any<AuthenticationProperties?>());
    [Fact] void should_not_continue_before_provider_selection() => _nextCalled.ShouldBeFalse();

    string BodyProperty(string name)
    {
        using var document = JsonDocument.Parse(_handler.Body);
        return document.RootElement.GetProperty(name).GetString()!;
    }

    sealed class StageIssuer : IInvitationAttestationIssuer
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

    sealed class RecordingProtector : IInvitationEntryStateProtector
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

    sealed class RecordingHandler : HttpMessageHandler
    {
        public HttpRequestMessage? Request { get; private set; }

        public string Body { get; private set; } = string.Empty;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Request = request;
            Body = await request.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }
}
