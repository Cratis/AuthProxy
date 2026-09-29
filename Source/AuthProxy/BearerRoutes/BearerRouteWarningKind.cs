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
}
