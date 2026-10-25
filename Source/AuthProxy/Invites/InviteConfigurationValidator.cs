// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Validates the invite configuration settings that control post-completion redirect behavior.
/// </summary>
sealed class InviteConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <summary>
    /// Validates one AuthProxy configuration instance.
    /// </summary>
    /// <param name="name">The options instance name.</param>
    /// <param name="options">The configuration to validate.</param>
    /// <returns>All configuration failures, or a successful validation result.</returns>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var invite = options.Invite;
        if (invite is null)
        {
            return ValidateOptionsResult.Success;
        }

        var failures = new List<string>();
        var destination = invite.MatchingTenantInvitationDestination;

        // Reject undefined enum values that may have been parsed from configuration.
        if (!Enum.IsDefined(destination))
        {
            failures.Add(
                $"Invite.MatchingTenantInvitationDestination has an undefined value '{(int)destination}'. " +
                $"Use '{nameof(C.InvitationCompletionDestination.ReturnUrl)}' or '{nameof(C.InvitationCompletionDestination.Lobby)}'.");
        }

        // Lobby destination requires TenantClaim to be set.
        if (destination == C.InvitationCompletionDestination.Lobby
            && string.IsNullOrWhiteSpace(invite.TenantClaim))
        {
            failures.Add(
                "Invite.MatchingTenantInvitationDestination is 'Lobby' but Invite.TenantClaim is not configured. " +
                "A tenant claim is required to determine which invitations match the resolved tenant.");
        }

        // Lobby destination requires Lobby.Frontend.BaseUrl to be set.
        if (destination == C.InvitationCompletionDestination.Lobby
            && string.IsNullOrWhiteSpace(invite.Lobby?.Frontend?.BaseUrl))
        {
            failures.Add(
                "Invite.MatchingTenantInvitationDestination is 'Lobby' but Invite.Lobby.Frontend.BaseUrl is not configured. " +
                "A Lobby frontend URL is required when matching-tenant invitations redirect to Lobby.");
        }

        ValidateMetadata(invite, failures);

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    static void ValidateMetadata(C.Invite invite, List<string> failures)
    {
        if (string.IsNullOrWhiteSpace(invite.TokenMetadataUrl))
        {
            return;
        }

        if (!BearerRouteTable.TryParseAuthorityUri(invite.TokenMetadataUrl, out _, out _))
        {
            failures.Add("Invite.TokenMetadataUrl must be an absolute HTTPS URL (HTTP is allowed only on loopback), without a query, fragment, or user information.");
        }
        if (string.IsNullOrWhiteSpace(invite.Issuer) || !string.Equals(invite.Issuer, invite.Issuer.Trim(), StringComparison.Ordinal))
        {
            failures.Add("Invite.Issuer is required without surrounding whitespace when Invite.TokenMetadataUrl is configured.");
        }
        if (string.IsNullOrWhiteSpace(invite.Audience) || !string.Equals(invite.Audience, invite.Audience.Trim(), StringComparison.Ordinal))
        {
            failures.Add("Invite.Audience is required without surrounding whitespace when Invite.TokenMetadataUrl is configured.");
        }
        if (!string.IsNullOrEmpty(invite.PublicKeyPem))
        {
            failures.Add("Invite.PublicKeyPem must be empty when Invite.TokenMetadataUrl is configured.");
        }
    }
}
