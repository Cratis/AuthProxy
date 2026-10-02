// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// The bearer-route deployment of <see cref="BearerRouteHarness"/>, with the gates the deployment declares for every
/// forwarded request: a proxy-wide claim requirement, a requirement of the service, and identity verification
/// required of the service.
/// </summary>
/// <remarks>
/// The service requires <c language="text">preferred_username</c> to be <see cref="BearerRouteHarness.GitHubLogin"/>. The
/// bearer route maps <c language="text">preferred_username</c> from the token's <c language="text">github_login</c>, so what is
/// checked is the principal after the mapping, not the token as issued. Every bearer route states that it
/// accepts callers without identity verification, which a deployment requiring verification must say.
/// <para>
/// The <see cref="BearerRouteHarness.ForwardingRoutePrefix"/> route leaves the deployment's requirements out and
/// requires <see cref="MembershipClaim"/> instead — the shape of a deployment whose requirements name a claim the
/// token issuer does not mint.
/// </para>
/// </remarks>
public class GatedBearerRouteHarness : BearerRouteHarness
{
    /// <summary>The claim the whole deployment requires.</summary>
    public const string RequiredClaim = "org";

    /// <summary>The value of <see cref="RequiredClaim"/> the deployment accepts.</summary>
    public const string RequiredValue = "Cratis";

    /// <summary>The claim the route ignoring the deployment's requirements requires instead.</summary>
    public const string MembershipClaim = "membership";

    /// <summary>The value of <see cref="MembershipClaim"/> that route accepts.</summary>
    public const string MembershipValue = "direct";

    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        const string service = $"{C.AuthProxy.SectionKey}:Services:app";

        settings[$"{C.Authorization.SectionKey}:RequiredClaims:0:Claim"] = RequiredClaim;
        settings[$"{C.Authorization.SectionKey}:RequiredClaims:0:AnyOf:0"] = RequiredValue;
        settings[$"{service}:Authorization:RequiredClaims:0:Claim"] = "preferred_username";
        settings[$"{service}:Authorization:RequiredClaims:0:AnyOf:0"] = GitHubLogin;
        settings[$"{service}:IdentityVerification"] = nameof(C.IdentityVerificationMode.Required);

        settings[$"{service}:BearerRoutes:1:{nameof(C.BearerRoute.IgnoreDeploymentRequiredClaims)}"] = "true";
        settings[$"{service}:BearerRoutes:1:{nameof(C.BearerRoute.RequiredClaims)}:0:Claim"] = MembershipClaim;
        settings[$"{service}:BearerRoutes:1:{nameof(C.BearerRoute.RequiredClaims)}:0:AnyOf:0"] = MembershipValue;

        for (var route = 0; route < 3; route++)
        {
            settings[$"{service}:BearerRoutes:{route}:{nameof(C.BearerRoute.AcceptWithoutIdentityVerification)}"] = "true";
        }
    }
}
