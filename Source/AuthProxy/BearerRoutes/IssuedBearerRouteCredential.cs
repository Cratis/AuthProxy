// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>The gate's verified credential decision, scoped to this request and route.</summary>
/// <param name="Route">The selected bearer route.</param>
/// <param name="Token">The credential verified at the gate.</param>
/// <param name="Payload">The verified client-credentials payload.</param>
/// <param name="ExpiresAt">The token's protected deadline.</param>
internal sealed record IssuedBearerRouteCredential(
    ResolvedBearerRoute Route,
    string Token,
    ClientCredentialsTokenPayload Payload,
    DateTimeOffset ExpiresAt)
{
    /// <summary>Stores the gate's decision under a typed request-local key.</summary>
    /// <param name="context">The request context.</param>
    /// <param name="credential">The verified credential decision.</param>
    internal static void Store(HttpContext context, IssuedBearerRouteCredential credential) =>
        context.Items[typeof(IssuedBearerRouteCredential)] = credential;

    /// <summary>Reads a decision made by the gate, if present.</summary>
    /// <param name="context">The request context.</param>
    /// <returns>The gate's decision or <see langword="null"/>.</returns>
    internal static IssuedBearerRouteCredential? Read(HttpContext context) =>
        context.Items[typeof(IssuedBearerRouteCredential)] as IssuedBearerRouteCredential;

    /// <summary>Checks the deadline and binding without decrypting the token a second time.</summary>
    /// <param name="route">The current bearer route.</param>
    /// <param name="prefix">The shared client-credentials prefix.</param>
    /// <param name="path">The current request path.</param>
    /// <param name="now">The current authentication time.</param>
    /// <returns>Whether this credential still belongs to this request's route.</returns>
    internal bool IsCurrentFor(ResolvedBearerRoute route, string prefix, PathString path, DateTimeOffset now) =>
        ExpiresAt > now && Route == route && ClientCredentialsOnBearerRoutes.IsIssuedFor(Payload, route, prefix, path);
}
