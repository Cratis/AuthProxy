// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

/// <summary>
/// Missing options are replaced by a default instance, so the claim strategy reads its default claim type.
/// </summary>
public class when_options_are_missing : a_tenant_resolver
{
    const string DefaultClaimType = "http://schemas.microsoft.com/identity/claims/tenantid";

    void Establish()
    {
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(DefaultClaimType, "tenant-abc")], "aad"));
        _resolver = CreateResolver(
            ConfigurationOf(
                new C.Tenants { ["tenant-one"] = new C.Tenant { Name = "Acme", SourceIdentifiers = ["tenant-abc"] } },
                Resolution(C.TenantSourceIdentifierResolverType.Claim)),
            new ClaimSourceIdentifierStrategy());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_resolve() => _succeeded.ShouldBeTrue();
    [Fact] void should_return_the_matching_tenant() => _result.TenantId.ShouldEqual("tenant-one");
}
