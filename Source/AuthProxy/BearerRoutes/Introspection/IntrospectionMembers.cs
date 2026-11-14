// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.Introspection;

/// <summary>The credential members published by Cratis Identity's RFC 7662 endpoint.</summary>
internal static class IntrospectionMembers
{
    /// <summary>The authoritative credential family.</summary>
    internal const string CredentialKind = "credential_kind";

    /// <summary>The authoritative grant UUID.</summary>
    internal const string CredentialId = "credential_id";

    /// <summary>The optional issuer cache revision.</summary>
    internal const string CacheEpoch = "cache_epoch";

    /// <summary>The supported unbound person grant family.</summary>
    internal const string OAuthGrant = "oauth-grant";
}
