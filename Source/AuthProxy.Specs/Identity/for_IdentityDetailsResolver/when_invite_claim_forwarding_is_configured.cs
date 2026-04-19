// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver;

public class when_invite_claim_forwarding_is_configured : Specification
{
    IdentityDetailsResolver _resolver;
    DefaultHttpContext _context;
    CapturingHttpMessageHandler _handler;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            Invite = new C.Invite
            {
                ClaimsToForward =
                [
                    new C.InviteClaimForwarding { FromClaimType = "organization_id", ToClaimType = "organization" },
                    new C.InviteClaimForwarding { FromClaimType = "invited_by" }
                ]
            },
            Services = new Dictionary<string, C.Service>
            {
                ["main"] = new() { Backend = new C.ServiceEndpoint { BaseUrl = "http://backend/" } }
            }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        _handler = new CapturingHttpMessageHandler();
        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(new HttpClient(_handler));

        var tokenValidator = Substitute.For<IInviteTokenValidator>();
        tokenValidator.TryGetClaim("invite-token", "jti", out Arg.Any<string>())
            .Returns(callInfo =>
            {
                callInfo[2] = "invite-jti";
                return true;
            });
        tokenValidator.TryGetClaim("invite-token", "organization_id", out Arg.Any<string>())
            .Returns(callInfo =>
            {
                callInfo[2] = "org-123";
                return true;
            });
        tokenValidator.TryGetClaim("invite-token", "invited_by", out Arg.Any<string>())
            .Returns(callInfo =>
            {
                callInfo[2] = "system-user";
                return true;
            });

        var enrichers = new IIdentityDetailsPrincipalEnricher[]
        {
            new InviteTokenClaimsPrincipalEnricher(tokenValidator, optionsMonitor)
        };

        _resolver = new IdentityDetailsResolver(
            optionsMonitor,
            httpClientFactory,
            enrichers,
            Substitute.For<ILogger<IdentityDetailsResolver>>());

        _context = new DefaultHttpContext();
        _context.Request.Headers.Cookie = $"{Cookies.InviteToken}=invite-token";
    }

    Task Because() =>
        _resolver.Resolve(
            _context,
            new ClientPrincipal
            {
                UserId = "identity-user-id",
                Claims =
                [
                    new ClientPrincipalClaim { Type = "given_name", Value = "Alice" }
                ]
            },
            Guid.NewGuid().ToString());

    [Fact] void should_preserve_user_id() => _handler.Principal?.UserId.ShouldEqual("identity-user-id");

    [Fact] void should_forward_mapped_invite_claim() =>
        _handler.Principal?.Claims.Any(_ => _.Type == "organization" && _.Value == "org-123").ShouldBeTrue();

    [Fact] void should_forward_invite_claim_with_original_type_when_target_is_not_set() =>
        _handler.Principal?.Claims.Any(_ => _.Type == "invited_by" && _.Value == "system-user").ShouldBeTrue();

    [Fact] void should_preserve_existing_identity_provider_claims() =>
        _handler.Principal?.Claims.Any(_ => _.Type == "given_name" && _.Value == "Alice").ShouldBeTrue();

    class CapturingHttpMessageHandler : HttpMessageHandler
    {
        public ClientPrincipal? Principal { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Headers.TryGetValues(Headers.Principal, out var values))
            {
                ClientPrincipal.TryFromBase64(values.Single(), out var principal);
                Principal = principal;
            }

            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(/*lang=json,strict*/ "{}")
            });
        }
    }
}
