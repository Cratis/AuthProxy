// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Refuses a configuration that requires identity verification without a way to resolve the tenant it is
/// verified against.
/// </summary>
/// <remarks>
/// Identity resolution is keyed by principal and tenant, so a deployment with no tenant resolution
/// configured resolves no tenant for anybody, on every request. Nothing about that looks broken: the proxy
/// starts, callers sign in, requests are forwarded, and the one thing that does not happen is the
/// authorization check the deployment asked for. The configuration is not merely degraded, it is inert —
/// and inert in the permissive direction, which is the direction nobody notices.
/// <para>
/// Refusing at startup is the only place this can be said out loud. At request time the proxy would have to
/// choose between refusing every caller of a deployment that is misconfigured rather than under attack, and
/// admitting them, and both answers are wrong for a condition that is a configuration mistake rather than a
/// property of the request. <see cref="C.AuthProxy.TenantResolutions"/> naming a strategy — even
/// <c>Specified</c>, for a single-tenant deployment — is what clears it.
/// </para>
/// </remarks>
public class IdentityVerificationConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options) =>
        options.RequiresIdentityVerification && options.TenantResolutions.Count == 0
            ? ValidateOptionsResult.Fail(
                $"A service declares {nameof(C.IdentityVerificationMode)}.{nameof(C.IdentityVerificationMode.Required)}, " +
                $"but {C.AuthProxy.SectionKey}:{nameof(C.AuthProxy.TenantResolutions)} is empty. Identity verification is " +
                "resolved per tenant, so with no tenant resolution configured no request would ever be verified and the " +
                $"setting would have no effect. Declare a tenant resolution — {nameof(C.TenantSourceIdentifierResolverType.Specified)} " +
                "with a tenant ID is the single-tenant one — or stop requiring verification.")
            : ValidateOptionsResult.Success;
}
