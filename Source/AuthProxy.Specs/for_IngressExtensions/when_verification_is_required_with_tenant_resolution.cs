// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_IngressExtensions.given;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.for_IngressExtensions;

/// <summary>
/// The positive control. The refusal is about a deployment that cannot resolve a tenant at all, not about
/// requiring verification — naming a single-tenant resolution is the whole fix, and it has to actually start.
/// </summary>
public class when_verification_is_required_with_tenant_resolution : an_ingress_configuration
{
    C.AuthProxy _config;

    protected override IDictionary<string, string?> IngressSettings => new Dictionary<string, string?>
    {
        [$"{C.AuthProxy.SectionKey}:Services:app:Backend:BaseUrl"] = "https://backend.example.com",
        [$"{C.AuthProxy.SectionKey}:Services:app:IdentityVerification"] = nameof(C.IdentityVerificationMode.Required),
        [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
        [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = "33333333-3333-3333-3333-333333333333",
    };

    void Because() => _config = _serviceProvider.GetRequiredService<IOptions<C.AuthProxy>>().Value;

    [Fact] void should_accept_the_configuration() => _config.RequiresIdentityVerification.ShouldBeTrue();
}
