// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_claim_strategy_resolves_from_claim_and_tenant_is_matched : Specification
{
    static readonly Guid _expectedTenantId = Guid.Parse("55555555-5555-5555-5555-555555555555");

    TenantResolver _resolver;
    DefaultHttpContext _context;
    bool _succeeded;
    Guid _tenantId;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            Tenants = new C.Tenants
            {
                [_expectedTenantId] = new C.Tenant { Name = "Acme", SourceIdentifiers = ["tenant-from-claim"] }
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

        var identity = new ClaimsIdentity([
            new Claim("tenant_claim", "tenant-from-claim")
        ],
        "aad");

        _context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(identity)
        };

        _resolver = new TenantResolver(optionsMonitor, [new ClaimSourceIdentifierStrategy()], Substitute.For<ILogger<TenantResolver>>());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _tenantId);

    [Fact] void should_succeed() => _succeeded.ShouldBeTrue();
    [Fact] void should_return_the_matched_tenant_id() => _tenantId.ShouldEqual(_expectedTenantId);
}
