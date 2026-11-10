// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>Writes fixed, non-cacheable DPoP machine challenges without Bearer downgrade hints.</summary>
internal static class DpopChallenge
{
    /// <summary>Preserves ordinary Bearer refusals and switches only opted-in DPoP presentations.</summary>
    /// <param name="context">The response context.</param>
    /// <param name="validation">The verdict.</param>
    /// <param name="route">The matched route.</param>
    internal static void Write(HttpContext context, BearerTokenValidation validation, ResolvedBearerRoute route)
    {
        if (UseBearer(context, validation, route))
        {
            BearerChallenge.Write(context, validation, route);
            return;
        }
        if (validation.Status == BearerTokenValidationStatus.InsufficientScope)
        {
            Refuse(context, route, "insufficient_scope", new(StatusCodes.Status403Forbidden, string.Join(' ', BearerTokenValidator.RequiredScopes(route))));
            return;
        }
        Refuse(context, route, validation.DpopError ?? "invalid_token");
    }

    /// <summary>Writes a proof, availability or nonce refusal with trusted metadata.</summary>
    /// <param name="context">The response context.</param>
    /// <param name="route">The route.</param>
    /// <param name="error">The fixed OAuth error code.</param>
    /// <param name="options">The trusted optional response details.</param>
    internal static void Refuse(HttpContext context, ResolvedBearerRoute route, string error, DpopChallengeOptions? options = null)
    {
        BearerChallenge.NoStore(context);
        var challenge = BearerChallenge.ChallengeValue(route.ResourceMetadataUrl, error, options?.Scope);
        context.Response.Headers.WWWAuthenticate = "DPoP" + challenge["Bearer".Length..] + ", algs=\"ES256\"";
        if (options?.Nonce is { } nonce) context.Response.Headers["DPoP-Nonce"] = nonce;
        MachineResponse.Write(context, options?.Status ?? StatusCodes.Status401Unauthorized, error);
    }

    static bool UseBearer(HttpContext context, BearerTokenValidation validation, ResolvedBearerRoute route) =>
        route.Route.Dpop is null || (route.Route.Dpop.Mode == Configuration.DpopMode.Accept && !DpopPresentation.IsDpop(context.Request)
        && validation.DpopError is null && validation.SenderConstraint is null);
}
