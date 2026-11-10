// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>Compares optional introspection evidence against the already verified JWT.</summary>
internal static class DpopIntrospection
{
    /// <summary>Preserves fail-closed introspection on DPoP routes.</summary>
    /// <param name="route">The route.</param>
    /// <returns>Whether the legacy availability opt-out can apply.</returns>
    internal static bool AllowsUnavailable(ResolvedBearerRoute route) => route.Route.Dpop is null && !BearerRouteTable.IsMcpPrefix(route.Prefix);

    /// <summary>Finds contradictory sender evidence, never introducing a constraint from introspection.</summary>
    /// <param name="root">The response.</param>
    /// <param name="validated">The JWT verdict.</param>
    /// <returns>The contradictory property, or null.</returns>
    internal static string? Contradiction(JsonElement root, BearerTokenValidation validated)
    {
        var confirmations = root.EnumerateObject().Where(property => string.Equals(property.Name, "cnf", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (validated.SenderConstraint is not null || confirmations.Length > 0)
        {
            if (!Matches(confirmations, validated.SenderConstraint)) return "cnf";
        }
        if (validated.SenderConstraint is not null && !DpopEncoding.Unique(root)) return "cnf";
        return TokenTypeContradiction(root, validated.SenderConstraint);
    }

    static string? TokenTypeContradiction(JsonElement root, DpopSenderConstraint? constraint)
    {
        if (!root.TryGetProperty("token_type", out var type)) return null;
        if (type.ValueKind == JsonValueKind.Null && constraint is null) return null;
        var expected = constraint is null ? "Bearer" : "DPoP";
        return type.ValueKind == JsonValueKind.String && string.Equals(type.GetString(), expected, StringComparison.OrdinalIgnoreCase) ? null : "token_type";
    }

    static bool Matches(JsonProperty[] confirmations, DpopSenderConstraint? constraint)
    {
        if (constraint is null || confirmations.Length != 1 || confirmations[0].Name != "cnf") return false;
        var value = confirmations[0].Value;
        return value.ValueKind == JsonValueKind.Object && value.EnumerateObject().Count() == 1
            && DpopEncoding.Equal(DpopEncoding.Text(value, "jkt") ?? string.Empty, constraint.Jkt);
    }
}
