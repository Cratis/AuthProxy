// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Defines invitation-capability claims AuthProxy understands before authentication.
/// </summary>
public static class InvitationCapabilityClaims
{
    /// <summary>
    /// The canonical provider key to which an immutable provider-subject invitation is restricted.
    /// </summary>
    public const string RecipientProviderKey = "recipient_provider_key";

    /// <summary>
    /// The opaque keyed identity binding independently verified by the invitation authority.
    /// </summary>
    public const string RecipientIdentityBinding = "recipient_identity_binding";
}
