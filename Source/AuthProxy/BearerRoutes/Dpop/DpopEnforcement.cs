// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>Enforces per-request proof, nonce and shared replay checks before forwarding.</summary>
/// <param name="store">The authoritative shared replay store.</param>
/// <param name="protection">The fleet-shared nonce key ring.</param>
/// <param name="clock">The deployment clock, checked against Redis.</param>
/// <param name="logger">The logger for fixed refusal reasons.</param>
/// <param name="options">The deployment's nonce policy.</param>
public sealed class DpopEnforcement(IDpopReplayStore store, IDataProtectionProvider protection, TimeProvider clock, ILogger<DpopEnforcement> logger, IOptions<C.AuthProxy> options)
{
    readonly DpopNonce _nonce = new(protection, clock);

    /// <summary>Verifies proofs on scope refusals without moving successful reservations ahead of introspection.</summary>
    /// <param name="enforcement">The optional service.</param>
    /// <param name="validator">The signed-token validator.</param>
    /// <param name="context">The request.</param>
    /// <param name="route">The route.</param>
    /// <returns>The signed-token verdict or null after a DPoP refusal.</returns>
    internal static async Task<BearerTokenValidation?> ValidateToken(DpopEnforcement? enforcement, IBearerTokenValidator validator, HttpContext context, ResolvedBearerRoute route)
    {
        var validation = await validator.Validate(context.Request, route, context.RequestAborted);
        return validation.Succeeded ? validation : await Verify(enforcement, context, route, validation);
    }

    /// <summary>Applies stateful enforcement after token introspection, without altering ordinary Bearer requests.</summary>
    /// <param name="enforcement">The configured service.</param>
    /// <param name="context">The request.</param>
    /// <param name="route">The matched route.</param>
    /// <param name="validation">The signed-token verdict.</param>
    /// <returns>The proof-verified verdict, or null after a machine refusal.</returns>
    internal static async Task<BearerTokenValidation?> Verify(DpopEnforcement? enforcement, HttpContext context, ResolvedBearerRoute route, BearerTokenValidation validation)
    {
        if (route.Route.Dpop is null || validation.SenderConstraint is null) return validation;
        if (validation.DpopError is not null)
        {
            if (enforcement is not null) return await enforcement.RefusePresentation(context, route, validation.SenderConstraint.Jkt);
            DpopChallenge.Write(context, validation, route);
            return null;
        }
        if (validation.Status is not (BearerTokenValidationStatus.Succeeded or BearerTokenValidationStatus.InsufficientScope)) return validation;
        if (enforcement is null)
        {
            DpopChallenge.Refuse(context, route, "invalid_dpop_proof");
            return null;
        }
        return await enforcement.VerifyRequest(context, route, validation);
    }

    /// <summary>Preserves the existing standard-base64 JSON sender-evidence wire contract.</summary>
    /// <param name="jkt">The verified thumbprint.</param>
    /// <param name="jti">The consumed proof identifier.</param>
    /// <returns>The evidence for the downstream envelope producer.</returns>
    internal static string SenderBinding(string jkt, string jti) => Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { jkt, jti })));

    /// <summary>Removes proof and access-token material only after sender-bound verification has succeeded.</summary>
    /// <param name="context">The request about to be forwarded.</param>
    /// <param name="validation">The proof-verified verdict.</param>
    internal static void PrepareForward(HttpContext context, BearerTokenValidation validation)
    {
        if (validation.SenderConstraint is null) return;
        context.Request.Headers.Remove("DPoP");
        context.Request.Headers.Remove("Authorization");
    }

    async Task<BearerTokenValidation?> VerifyRequest(HttpContext context, ResolvedBearerRoute route, BearerTokenValidation validation)
    {
        if (await store.CheckHealth(context.RequestAborted) != DpopReplayResult.Accepted) return Refuse(context, route, "jti_cache_unavailable");
        var jkt = validation.SenderConstraint!.Jkt;
        var proof = ReadProof(context.Request, route, jkt);
        if (proof.Status != DpopProofStatus.Valid) return Refuse(context, route, proof.Reason, jkt);
        if (options.Value.Dpop.NonceRequired && !_nonce.Valid(proof.Nonce, route, jkt))
        {
            logger.Refused("nonce_required");
            DpopChallenge.Refuse(context, route, "use_dpop_nonce", new(Nonce: _nonce.Create(route, jkt)));
            return null;
        }
        return await Consume(context, route, validation, proof);
    }

    async Task<BearerTokenValidation?> Consume(HttpContext context, ResolvedBearerRoute route, BearerTokenValidation validation, DpopProofResult proof)
    {
        var jkt = proof.Jkt!;
        DpopTargetUri.TryOrigin(route.Route.Dpop!.PublicOrigin, out var origin);
        var consumed = await store.TryConsume(origin, jkt, proof.Jti!, context.RequestAborted);
        if (consumed == DpopReplayResult.Unavailable) return Refuse(context, route, "jti_cache_unavailable");
        if (consumed == DpopReplayResult.Replay) return Refuse(context, route, "replayed_jti", jkt);
        if (options.Value.Dpop.NonceRequired) context.Response.Headers["DPoP-Nonce"] = _nonce.Create(route, jkt);
        return validation with { SenderBinding = SenderBinding(jkt, proof.Jti!) };
    }

    async Task<BearerTokenValidation?> RefusePresentation(HttpContext context, ResolvedBearerRoute route, string jkt)
    {
        var healthy = await store.CheckHealth(context.RequestAborted) == DpopReplayResult.Accepted;
        return Refuse(context, route, healthy ? "bound_token_as_bearer" : "jti_cache_unavailable", healthy ? jkt : null);
    }

    DpopProofResult ReadProof(HttpRequest request, ResolvedBearerRoute route, string jkt)
    {
        if (!DpopPresentation.IsDpop(request)) return DpopProofResult.Invalid("bound_token_as_bearer");
        var proofs = request.Headers["DPoP"];
        if (proofs.Count != 1 || string.IsNullOrEmpty(proofs[0])) return DpopProofResult.Invalid("missing_or_multiple_proofs");
        if (!DpopTargetUri.TryBuild(request, route.Route, out var target)) return DpopProofResult.Invalid("invalid_htu");
        if (!BearerTokenValidator.TryReadStrictBearerToken(request, out var token)) return DpopProofResult.Invalid("malformed_authorization");
        return DpopProofVerifier.Verify(proofs[0]!, new(request.Method, target, token, jkt, clock.GetUtcNow().ToUnixTimeSeconds()));
    }

    BearerTokenValidation? Refuse(HttpContext context, ResolvedBearerRoute route, string reason, string? jkt = null)
    {
        logger.Refused(reason);
        var nonce = options.Value.Dpop.NonceRequired && jkt is not null ? _nonce.Create(route, jkt) : null;
        DpopChallenge.Refuse(context, route, "invalid_dpop_proof", new(Nonce: nonce));
        return null;
    }
}
