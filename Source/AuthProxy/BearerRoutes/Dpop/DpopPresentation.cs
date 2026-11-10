// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>Keeps sender constraints and presentation schemes distinct from ordinary bearer credentials.</summary>
internal static class DpopPresentation
{
    /// <summary>Reads only a unique, exact cnf.jkt confirmation on an opted-in route.</summary>
    /// <param name="route">The route.</param>
    /// <param name="claims">The signed JWT claims.</param>
    /// <param name="constraint">The validated confirmation.</param>
    /// <returns>Whether the confirmation policy is satisfied.</returns>
    internal static bool TryConstraint(ResolvedBearerRoute route, Claim[] claims, out DpopSenderConstraint? constraint)
    {
        constraint = null;
        var confirmations = claims.Where(claim => string.Equals(claim.Type, "cnf", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (confirmations.Length == 0) return true;
        if (route.Route.Dpop is null || confirmations.Length != 1) return false;
        try
        {
            using var document = JsonDocument.Parse(confirmations[0].Value, new JsonDocumentOptions { MaxDepth = 4 });
            var root = document.RootElement;
            if (!SingleConfirmation(root)) return false;
            var jkt = DpopEncoding.Text(root, "jkt");
            if (jkt is null || !DpopEncoding.IsThumbprint(jkt)) return false;
            constraint = new(jkt);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>Refuses bound tokens as Bearer and unbound tokens as DPoP.</summary>
    /// <param name="request">The presentation.</param>
    /// <param name="route">The route.</param>
    /// <param name="validation">The signed-token verdict.</param>
    /// <returns>The presentation-aware verdict.</returns>
    internal static BearerTokenValidation Check(HttpRequest request, ResolvedBearerRoute route, BearerTokenValidation validation)
    {
        if (validation.Status is not (BearerTokenValidationStatus.Succeeded or BearerTokenValidationStatus.InsufficientScope)) return validation;
        var error = PresentationError(request, route, validation);
        return error is null ? validation : Refused(validation, error);
    }

    /// <summary>Prevents DPoP from entering PAT or local-token dispatch on routes without opt-in.</summary>
    /// <param name="context">The request.</param>
    /// <param name="route">The route.</param>
    /// <returns>Whether the request was refused.</returns>
    internal static bool RefuseUnsupported(HttpContext context, ResolvedBearerRoute route)
    {
        if (!IsDpop(context.Request) || route.Route.Dpop is not null) return false;
        BearerChallenge.Write(context, BearerTokenValidation.Refused(BearerTokenValidationStatus.Invalid, BearerTokenValidator.SenderConstrainedTokenReason), route);
        return true;
    }

    /// <summary>Recognizes a single DPoP presentation.</summary>
    /// <param name="request">The request.</param>
    /// <returns>Whether the scheme is DPoP.</returns>
    internal static bool IsDpop(HttpRequest request) => request.Headers.Authorization.Count == 1 && request.Headers.Authorization[0]?.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>Selects the scheme to inspect for outside-route rejection only.</summary>
    /// <param name="value">The authorization value.</param>
    /// <returns>The scheme name.</returns>
    internal static string LenientScheme(string value) => value.AsSpan().TrimStart().StartsWith("DPoP", StringComparison.OrdinalIgnoreCase) ? "DPoP" : "Bearer";

    /// <summary>Recognizes strict Bearer or DPoP prefixes without permitting whitespace aliases.</summary>
    /// <param name="value">The authorization value.</param>
    /// <param name="length">The prefix length.</param>
    /// <returns>Whether the scheme was recognized.</returns>
    internal static bool IsTokenScheme(string value, out int length)
    {
        length = value.StartsWith("DPoP ", StringComparison.OrdinalIgnoreCase) ? 5 : 7;
        return length == 5 || value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase);
    }

    static bool SingleConfirmation(JsonElement root) => root.ValueKind == JsonValueKind.Object && root.EnumerateObject().Count() == 1 && DpopEncoding.Unique(root);

    static string? PresentationError(HttpRequest request, ResolvedBearerRoute route, BearerTokenValidation validation)
    {
        if (validation.SenderConstraint is not null) return IsDpop(request) ? null : "invalid_dpop_proof";
        if (IsDpop(request)) return "invalid_token";
        if (route.Route.Dpop is null) return null;
        return UnboundError(request, route.Route.Dpop.Mode);
    }

    static string? UnboundError(HttpRequest request, Configuration.DpopMode mode)
    {
        if (mode == Configuration.DpopMode.Require) return "invalid_token";
        return request.Headers.ContainsKey("DPoP") ? "invalid_dpop_proof" : null;
    }

    static BearerTokenValidation Refused(BearerTokenValidation validation, string error) =>
        validation with { Status = BearerTokenValidationStatus.Invalid, Reason = "dpop_presentation_refused", DpopError = error };
}
