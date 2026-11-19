// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using Cratis.AuthProxy.Tenancy;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Cratis.AuthProxy.BearerRoutes.TokenExchange;

/// <summary>Exchanges only allow-listed issuers, for an independently addressed and verified tenant.</summary>
/// <param name="client">The Identity client.</param>
/// <param name="cache">The bounded single-flight cache.</param>
/// <param name="tenantResolver">The independent target resolvers.</param>
/// <param name="tenantVerifier">The tenant existence check.</param>
public sealed class BearerTokenExchange(ITokenExchangeClient client, TokenExchangeCache cache, ITenantResolver tenantResolver, ITenantVerifier tenantVerifier)
{
    static readonly object _attemptKey = new();

    /// <summary>Replaces opted-in external credentials before normal validation; never falls back after refusal.</summary>
    /// <param name="context">The request.</param>
    /// <param name="route">The trusted route.</param>
    /// <returns>Whether normal validation may proceed.</returns>
    public async Task<bool> Prepare(HttpContext context, ResolvedBearerRoute route)
    {
        context.Items.Remove(_attemptKey);
        if (route.Route.TokenExchange is not { } configuration) return true;
        var token = Subject(context);
        var issuer = configuration.Issuers.FirstOrDefault(_ => _.Issuer == Read(token)?.Issuer);
        if (issuer is null) return true;
        try
        {
            var tenant = Target(context);
            if (tenant is null || !await tenantVerifier.VerifyAsync(tenant).WaitAsync(context.RequestAborted)) return Forbidden(context);
            return await Obtain(context, route, issuer, token, tenant);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            return false;
        }
        catch (Exception)
        {
            // No exception text or credential material may enter diagnostics or responses.
            return Refuse(context, route, new(TokenExchangeVerdict.Unavailable));
        }
    }

    /// <summary>Checks raw signed claims after normal JWT validation, before introspection or forwarding.</summary>
    /// <param name="context">The request.</param>
    /// <param name="route">The trusted route.</param>
    /// <param name="validation">The normal JWT validation result.</param>
    /// <returns>Whether every exchange post-condition agrees.</returns>
    public bool Confirm(HttpContext context, ResolvedBearerRoute route, BearerTokenValidation validation)
    {
        if (context.Items[_attemptKey] is not Attempt attempt) return true;
        var configuration = route.Route.TokenExchange!;
        var jwt = Read(attempt.Token);
        if (!MatchesValidation(validation, configuration) || !MatchesToken(jwt, configuration))
        {
            Evict(context);
            return Refuse(context, route, new(TokenExchangeVerdict.Refused));
        }
        if (MatchesBinding(validation, jwt!, attempt))
        {
            return true;
        }
        Evict(context);
        return Forbidden(context);
    }

    /// <summary>Evicts a result refused by any subsequent JWT, activity or authorization check.</summary>
    /// <param name="context">The request.</param>
    public void Evict(HttpContext context)
    {
        if (context.Items[_attemptKey] is Attempt attempt) cache.Evict(attempt.Key);
    }

    /// <summary>Normalizes failed validation of an exchanged token to an invalid-token refusal.</summary>
    /// <param name="context">The request.</param>
    /// <param name="route">The trusted route.</param>
    /// <param name="validation">The failed JWT validation result.</param>
    /// <returns>Whether an exchange-specific refusal was written.</returns>
    internal bool RefuseValidationFailure(HttpContext context, ResolvedBearerRoute route, BearerTokenValidation validation)
    {
        if (context.Items[_attemptKey] is not Attempt || validation.Status == BearerTokenValidationStatus.InsufficientScope) return false;
        Refuse(context, route, new(TokenExchangeVerdict.Refused));
        return true;
    }

    static bool MatchesValidation(BearerTokenValidation validation, Configuration.BearerTokenExchange configuration) =>
        validation.Succeeded && validation.Issuer?.Issuer == configuration.ResultIssuer;

    static bool MatchesToken(JsonWebToken? jwt, Configuration.BearerTokenExchange configuration) =>
        jwt?.Issuer == configuration.ResultIssuer && jwt.Audiences.Contains(configuration.Audience, StringComparer.Ordinal);

    static bool MatchesBinding(BearerTokenValidation validation, JsonWebToken jwt, Attempt attempt) =>
        CredentialTarget.Matches(validation.TenantId, attempt.Tenant)
        && SingleClaim(jwt, "idp", attempt.Issuer) && SingleClaim(jwt, "tenant_id", attempt.Tenant);

    static bool HasTenant(JsonWebToken? jwt)
    {
        var tenants = jwt?.Claims.Where(_ => _.Type == "tenant_id").ToArray();
        return tenants is { Length: 1 } && TenantIdentifier.IsUsable(tenants[0].Value);
    }

    static bool SingleClaim(JsonWebToken jwt, string type, string value)
    {
        var claims = jwt.Claims.Where(_ => _.Type == type).ToArray();
        return claims.Length == 1 && CredentialTarget.Matches(claims[0].Value, value);
    }

    static string Subject(HttpContext context)
    {
        var header = context.Request.Headers.Authorization.ToString();
        return header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? header[7..].Trim() : string.Empty;
    }

    static JsonWebToken? Read(string? token)
    {
        try { return string.IsNullOrEmpty(token) ? null : new JsonWebToken(token); }
        catch (Exception) { return null; }
    }

    static bool Forbidden(HttpContext context)
    {
        BearerChallenge.Forbidden(context);
        return false;
    }

    static bool Refuse(HttpContext context, ResolvedBearerRoute route, TokenExchangeResult result)
    {
        var unavailable = result.Verdict == TokenExchangeVerdict.Unavailable;
        var validation = BearerTokenValidation.Refused(BearerTokenValidationStatus.Invalid, "Token exchange refused.");
        BearerChallenge.Write(context, validation, route);
        if (unavailable && result.RetryAfter is >= 0 and <= 60) context.Response.Headers.RetryAfter = result.RetryAfter.Value.ToString(CultureInfo.InvariantCulture);
        return false;
    }

    async Task<bool> Obtain(HttpContext context, ResolvedBearerRoute route, Configuration.BearerTokenExchangeIssuer issuer, string token, string tenant)
    {
        var configuration = route.Route.TokenExchange!;
        var key = TokenExchangeCache.CreateKey(configuration, issuer.Issuer, tenant, token);
        var result = await cache.GetOrExchange(key, configuration.MaximumCachedTokens, () => client.Exchange(configuration, issuer, token, tenant, context.RequestAborted), context.RequestAborted);
        if (result.Verdict != TokenExchangeVerdict.Success) return Refuse(context, route, result);
        var jwt = Read(result.Token);
        if (jwt?.Issuer != configuration.ResultIssuer || !HasTenant(jwt))
        {
            cache.Evict(key);
            return Refuse(context, route, new(TokenExchangeVerdict.Refused));
        }
        context.Request.Headers.Authorization = "Bearer " + result.Token;
        context.Items[_attemptKey] = new Attempt(key, tenant, issuer.Issuer, result.Token!);
        return true;
    }

    string? Target(HttpContext context)
    {
        var targets = tenantResolver.ResolveEach(context).Where(_ => CredentialTarget.IsAddressedByRequest(_.Strategy, bearerRoute: true)).ToArray();
        if (targets.Length == 0) return null;
        var tenant = targets[0].TenantId;
        return !string.IsNullOrWhiteSpace(tenant) && targets.All(_ => CredentialTarget.Matches(_.TenantId, tenant)) ? tenant : null;
    }

    sealed record Attempt(string Key, string Tenant, string Issuer, string Token)
    {
        public override string ToString() => nameof(Attempt);
    }
}
