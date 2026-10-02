// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Represents something a bearer route does not check that the rest of the deployment does.
/// </summary>
/// <param name="Kind">What is not checked.</param>
/// <param name="ServiceName">The service the route belongs to.</param>
/// <param name="Prefix">The route's path prefix.</param>
/// <param name="Subjects">What the warning is about: the claim types left out, or the services not consulted.</param>
public sealed record BearerRouteWarning(
    BearerRouteWarningKind Kind,
    string ServiceName,
    string Prefix,
    IReadOnlyList<string> Subjects);
