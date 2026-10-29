// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_a_claim_value_is_not_a_usable_tenant_identifier : Specification
{
    TenantResolver _resolver;
    DefaultHttpContext _context;
    bool _succeeded;
    string _tenantId = string.Empty;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            Tenants = new C.Tenants
            {
                ["tenant-one"] = new C.Tenant { Name = "Acme", SourceIdentifiers = ["a b", "a/b", "tenant-abc"] }
            },
            TenantResolutions =
            [
                new C.TenantResolution
                {
                    Strategy = C.TenantSourceIdentifierResolverType.Claim,
                    Options = new ClaimOptions { ClaimType = "tenant_claim" }
                }
            ]
        };

        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        _context = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("tenant_claim", "a b")], "aad")) };
        _resolver = new TenantResolver(optionsMonitor, [new ClaimSourceIdentifierStrategy()], Substitute.For<ILogger<TenantResolver>>());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _tenantId);

    [Fact] void should_not_resolve() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_return_a_tenant() => _tenantId.ShouldEqual(string.Empty);
}
