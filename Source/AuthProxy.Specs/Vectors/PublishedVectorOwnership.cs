// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Vectors;

public static class PublishedVectorOwnership
{
    public static IReadOnlyDictionary<string, string> NotApplicable { get; } = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["oauth-only-resource-discovery"] = "The backend serves the metadata document; AuthProxy forwards it without constructing its body.",
        ["combined-resource-discovery"] = "The backend serves the metadata document; AuthProxy forwards it without constructing its body.",
        ["authorization-resource-required"] = "Identity validates resource indicators on authorization requests; AuthProxy is not the authorization server.",
        ["token-resource-required"] = "Identity validates resource indicators during code exchange; AuthProxy does not exchange authorization codes.",
        ["token-resource-must-match"] = "Identity binds authorization codes to resources during code exchange.",
        ["oauth-only-step-up-retry-limit"] = "The OAuth client owns step-up retry state; AuthProxy only returns the insufficient_scope challenge.",
        ["combined-step-up-retry-limit"] = "The OAuth client owns step-up retry state; AuthProxy only returns the insufficient_scope challenge.",
        ["client-requires-pkce-metadata"] = "The OAuth client checks authorization-server PKCE metadata.",
        ["client-selects-s256"] = "The OAuth client selects the PKCE challenge method.",
        ["pat-policy-denial-no-oauth-step-up"] = "The backend verifies PATs and applies PAT product policy; AuthProxy only recognizes and forwards them.",
        ["discovery-resource-must-match"] = "The OAuth client validates discovered resource metadata against its requested resource.",
        ["authorization-requires-registered-resource"] = "Identity owns resource registration and authorization requests.",
        ["authorization-rejects-plain-pkce"] = "Identity validates PKCE on authorization requests.",
        ["authorization-requires-pkce"] = "Identity requires PKCE on authorization requests.",
        ["unbound-envelope-plus-bearer-is-ambiguous"] = "Arc consumes AuthProxy identity envelopes and rejects unbound envelopes; AuthProxy produces envelopes, not callers from inbound envelopes.",
        ["bound-envelope-builds-caller-from-bearer"] = "Arc constructs the backend caller from the verified bearer and AuthProxy envelope.",
        ["envelope-kind-must-match-bearer"] = "Arc verifies the envelope credential kind against the bearer.",
        ["revoked-pat-envelope-no-oauth-fallback"] = "Arc verifies PAT revocation and the forwarded envelope; AuthProxy does not verify PATs.",
        ["envelope-subject-must-match-bearer"] = "Arc compares the forwarded envelope subject with the backend-verified bearer subject.",
    };
}
