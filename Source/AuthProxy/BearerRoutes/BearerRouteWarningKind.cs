// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Represents a way a bearer route admits callers a browser session in the same deployment would not be admitted
/// on, which the operator is told about at startup.
/// </summary>
public enum BearerRouteWarningKind
{
    /// <summary>
    /// The route sets <see cref="Configuration.BearerRoute.IgnoreDeploymentRequiredClaims"/>, leaving out claim
    /// requirements the deployment declares.
    /// </summary>
    DeploymentRequirementsIgnored = 0,

    /// <summary>
    /// Services answer <c language="text">/.cratis/me</c> for browser sessions, and an HTTP <c language="text">403</c> from one
    /// refuses a browser session even under <see cref="Configuration.IdentityVerificationMode.BestEffort"/>. A
    /// bearer route never calls it, so that refusal never happens there, and the route does not say it accepts
    /// that through <see cref="Configuration.BearerRoute.AcceptWithoutIdentityVerification"/>.
    /// </summary>
    IdentityVerificationNotConsulted = 1,
}
