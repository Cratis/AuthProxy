// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;
using System.Text.Json;
using Cratis.AuthProxy.Invites;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;

public class an_oauth_verified_email_callback : configured_canonical_provider_callbacks
{
    protected OAuthCreatingTicketContext _context;
    protected ResponseHandler _handler;

    protected virtual bool HasInvitationState => true;
    protected virtual bool FailVerifiedEmailTransport => false;
    protected virtual HttpStatusCode VerifiedEmailStatusCode => HttpStatusCode.OK;
    protected virtual string VerifiedEmailResponse =>
        """[{"email":"verified@example.com","primary":true,"verified":true}]""";

    void Establish()
    {
        var identity = new ClaimsIdentity(
        [
            new Claim("email", "untrusted@example.com"),
            new Claim("email_verified", bool.TrueString.ToLowerInvariant()),
        ],
        "github");
        var principal = new ClaimsPrincipal(identity);
        _handler = new(
            () => VerifiedEmailResponse,
            () => VerifiedEmailStatusCode,
            () => FailVerifiedEmailTransport);
        var backchannel = new HttpClient(_handler);
        var tokenDocument = JsonDocument.Parse("""{"access_token":"access-token","token_type":"Bearer"}""");
        var tokenResponse = OAuthTokenResponse.Success(tokenDocument);
        var userDocument = JsonDocument.Parse("""{"id":"github-subject","email":"untrusted@example.com"}""");
        var scheme = new AuthenticationScheme("github", "github", typeof(OAuthHandler<OAuthOptions>));
        var properties = new AuthenticationProperties();
        if (HasInvitationState)
        {
            properties.Items[InvitationAuthenticationState.TransactionStateKey] = "transaction";
            properties.Items[InvitationAuthenticationState.ChallengeStateKey] = "challenge";
            properties.Items[InvitationAuthenticationState.CapabilityHashStateKey] = "capability-hash";
        }
        _context = new OAuthCreatingTicketContext(
            principal,
            properties,
            Context(),
            scheme,
            _oauthOptions,
            backchannel,
            tokenResponse,
            userDocument.RootElement);
    }

    protected Task InvokeCallback() => _oauthOptions.Events.OnCreatingTicket(_context);

    protected sealed class ResponseHandler(
        Func<string> verifiedEmailResponse,
        Func<HttpStatusCode> verifiedEmailStatusCode,
        Func<bool> failVerifiedEmailTransport) : HttpMessageHandler
    {
        public int VerifiedEmailRequests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var isVerifiedEmailRequest = request.RequestUri?.AbsolutePath.EndsWith("/emails", StringComparison.Ordinal) == true;
            if (isVerifiedEmailRequest)
            {
                VerifiedEmailRequests++;
                if (failVerifiedEmailTransport())
                {
                    throw new HttpRequestException("Simulated verified-email transport failure.");
                }
            }

            var content = request.RequestUri?.AbsolutePath switch
            {
                string path when path.EndsWith("/emails", StringComparison.Ordinal) => verifiedEmailResponse(),
                string path when path.EndsWith("/orgs", StringComparison.Ordinal) => """[{"login":"Cratis"}]""",
                string path when path.EndsWith("/teams", StringComparison.Ordinal) => """[{"slug":"ada","organization":{"login":"Cratis"}}]""",
                _ => """{"id":"github-subject","email":"untrusted@example.com"}"""
            };
            return Task.FromResult(new HttpResponseMessage(
                isVerifiedEmailRequest ? verifiedEmailStatusCode() : HttpStatusCode.OK)
            {
                Content = new StringContent(content, Encoding.UTF8, "application/json"),
            });
        }
    }
}
