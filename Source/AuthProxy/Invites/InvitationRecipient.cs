// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>The recipient an attested invitation is bound to.</summary>
/// <param name="ProviderKey">The identity-bound recipient's provider key, or empty for email-targeted recipients.</param>
/// <param name="InvitedEmail">The email-targeted recipient's invited address, or empty for identity-bound recipients.</param>
readonly record struct InvitationRecipient(string ProviderKey, string InvitedEmail);
