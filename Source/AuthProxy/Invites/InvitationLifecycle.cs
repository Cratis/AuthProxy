// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Stages an invitation with the backend, binds it to the provider challenge and completes it after sign-in, for
/// <see cref="InviteMiddleware"/>. Registered by <see cref="InvitesServiceCollectionExtensions.AddInvites"/>.
/// </summary>
public sealed class InvitationLifecycle
{
    readonly InviteCompletion _completion;
    readonly IOptionsMonitor<C.AuthProxy> _config;
    readonly ITenantResolver _tenantResolver;
    readonly IHttpClientFactory _httpClientFactory;
    readonly ILogger<InviteMiddleware> _logger;
    readonly IInvitationAttestationIssuer? _attestationIssuer;
    readonly IInvitationEntryStateProtector? _entryStateProtector;

    /// <summary>
    /// Initializes a new instance of the <see cref="InvitationLifecycle"/> class.
    /// </summary>
    /// <param name="completion">The shared invitation completion.</param>
    /// <param name="config">The auth proxy configuration monitor.</param>
    /// <param name="tenantResolver">The tenant resolver used to capture tenant metadata in authentication state.</param>
    /// <param name="httpClientFactory">The HTTP client factory used for the stage call.</param>
    /// <param name="logger">The logger, typed to the middleware so the log category does not drift.</param>
    /// <param name="attestationIssuer">The signed invitation-attestation issuer, or <see langword="null"/> when staging is unavailable.</param>
    /// <param name="entryStateProtector">The protected invitation-entry state service, or <see langword="null"/> when staging is unavailable.</param>
    internal InvitationLifecycle(
        InviteCompletion completion,
        IOptionsMonitor<C.AuthProxy> config,
        ITenantResolver tenantResolver,
        IHttpClientFactory httpClientFactory,
        ILogger<InviteMiddleware> logger,
        IInvitationAttestationIssuer? attestationIssuer,
        IInvitationEntryStateProtector? entryStateProtector)
    {
        _completion = completion;
        _config = config;
        _tenantResolver = tenantResolver;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _attestationIssuer = attestationIssuer;
        _entryStateProtector = entryStateProtector;
    }

    /// <summary>
    /// Stages the invitation with the backend.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="inviteToken">The validated invitation capability.</param>
    /// <returns>The staged entry state, or <see langword="null"/> when the invitation could not be staged.</returns>
    internal async Task<InvitationEntryState?> Stage(HttpContext context, string inviteToken)
    {
        var invite = _config.CurrentValue.Invite;
        var entryState = TryCreateEntryState(context, inviteToken, invite);
        if (entryState is null
            || !_attestationIssuer!.TryIssueStage(entryState, out var attestation))
        {
            return null;
        }

        var body = new InvitationStageRequest(
            entryState.InvitationTransaction,
            inviteToken,
            entryState.InvitationChallenge);
        var staged = await PostStageRequest(context, invite!, attestation, body);
        return staged ? entryState : null;
    }

    /// <summary>
    /// Protects a staged entry state for the browser round trip.
    /// </summary>
    /// <param name="state">The staged entry state.</param>
    /// <returns>The protected state.</returns>
    internal string ProtectEntryState(InvitationEntryState state) => _entryStateProtector!.Protect(state);

    /// <summary>
    /// Creates the provider challenge properties bound to the invitation.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="inviteToken">The invitation capability the challenge is started for.</param>
    /// <param name="entryState">The staged entry state, or <see langword="null"/> when nothing was staged.</param>
    /// <param name="properties">The challenge properties.</param>
    /// <returns><see langword="true"/> when the challenge is bound to the invitation; otherwise <see langword="false"/>.</returns>
    internal bool TryCreateChallengeProperties(
        HttpContext context,
        string inviteToken,
        InvitationEntryState? entryState,
        out AuthenticationProperties properties)
    {
        var returnUrl = context.GetPathAndQuery();
        properties = TenantAuthenticationState.CreateChallengeProperties(context, _tenantResolver, returnUrl);
        if (entryState is not null)
        {
            InvitationAuthenticationState.Bind(properties, entryState);
            return true;
        }

        if (InvitationAuthenticationState.TryBindPendingInvitation(context, properties))
        {
            // Nothing was staged, so bind the capability this challenge is being started for. It is
            // what proves, on the way back, that the session completing the invitation is the one
            // this invitation challenged for. The request's own cookie cannot say so — it is being
            // written by this very response.
            InvitationAuthenticationState.BindCapability(properties, inviteToken);
            return true;
        }

        return false;
    }

    /// <summary>
    /// Completes the invitation with the identity that answered its challenge.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="inviteToken">The re-validated invitation capability.</param>
    /// <returns>The outcome of the exchange.</returns>
    internal Task<InviteExchangeResult> Exchange(HttpContext context, string inviteToken) =>
        _completion.ExchangeForRequest(context, inviteToken);

    /// <summary>
    /// Resolves the lobby redirect for a completed invitation.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="inviteToken">The invitation capability.</param>
    /// <param name="lobbyRedirectUrl">The lobby redirect URL when one applies.</param>
    /// <returns><see langword="true"/> when a lobby redirect applies; otherwise <see langword="false"/>.</returns>
    internal bool TryResolveLobbyRedirect(HttpContext context, string inviteToken, out string lobbyRedirectUrl) =>
        _completion.TryResolveLobbyRedirect(context, inviteToken, out lobbyRedirectUrl);

    static bool IsStagingConfigured([NotNullWhen(true)] C.Invite? invite, string inviteToken) =>
        invite is not null
        && inviteToken.Length <= InviteCompletion.MaximumAttestedInvitationTokenLength
        && !string.IsNullOrWhiteSpace(invite.StageUrl)
        && !string.IsNullOrWhiteSpace(invite.TenantClaim);

    InvitationEntryState? TryCreateEntryState(HttpContext context, string inviteToken, C.Invite? invite)
    {
        if (!IsStagingConfigured(invite, inviteToken)
            || _attestationIssuer is null
            || _entryStateProtector is null
            || !InviteCompletion.TryGetSingleTokenClaim(inviteToken, JwtRegisteredClaimNames.Jti, out var invitationId)
            || !InviteCompletion.TryGetSingleTokenClaim(inviteToken, invite.TenantClaim, out var tenantId)
            || !_completion.ResolvedTenantMatchesWhenPresent(context, tenantId))
        {
            return null;
        }

        return new InvitationEntryState(
            tenantId,
            invitationId,
            InvitationAttestationIssuer.CreateOpaqueValue(),
            InvitationAttestationIssuer.CreateOpaqueValue(),
            InvitationAuthenticationState.ComputeCapabilityHash(inviteToken),
            DateTimeOffset.UtcNow.AddMinutes(15));
    }

    async Task<bool> PostStageRequest(
        HttpContext context,
        C.Invite invite,
        string attestation,
        InvitationStageRequest body)
    {
        using var client = _httpClientFactory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, invite.StageUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", attestation);
        request.Content = JsonContent.Create(body);

        try
        {
            using var response = await client.SendAsync(request, context.RequestAborted);
            if (response.IsSuccessStatusCode)
            {
                return true;
            }

            _logger.InviteExchangeEndpointFailed((int)response.StatusCode);
        }
        catch (Exception exception)
        {
            _logger.FailedToCallInviteExchangeEndpoint(exception, invite.StageUrl);
        }

        return false;
    }
}
