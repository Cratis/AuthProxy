// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

/// <summary>
/// Factory variant that adds <c>ClaimsToForward</c> configuration so that the
/// <c>organization_id</c> claim from the invite token is forwarded as <c>organization</c>
/// to the identity details provider.
/// </summary>
public class ClaimsForwardingAuthProxyFactory : AuthProxyFactory
{
    public const string OrganizationId = "test-org-123";
    public const string FromClaimType = "organization_id";
    public const string ToClaimType = "organization";

    /// <inheritdoc/>
    protected override IEnumerable<KeyValuePair<string, string?>> GetAdditionalConfiguration()
    {
        yield return new($"{C.AuthProxy.SectionKey}:Invite:ClaimsToForward:0:FromClaimType", FromClaimType);
        yield return new($"{C.AuthProxy.SectionKey}:Invite:ClaimsToForward:0:ToClaimType", ToClaimType);
    }
}
