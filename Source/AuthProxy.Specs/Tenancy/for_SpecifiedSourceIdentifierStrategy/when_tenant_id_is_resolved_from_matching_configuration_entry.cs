// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_SpecifiedSourceIdentifierStrategy;

public class when_tenant_id_is_resolved_from_matching_configuration_entry : Specification
{
    SpecifiedSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    SpecifiedOptions _options;
    bool _succeeded;
    string _sourceIdentifier;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            TenantResolutions =
            [
                new C.TenantResolution
                {
                    Strategy = C.TenantSourceIdentifierResolverType.Route,
                    Options = new JsonObject { ["tenantId"] = "should-not-be-used" }
                },
                new C.TenantResolution
                {
                    Strategy = C.TenantSourceIdentifierResolverType.Specified,
                    Options = new JsonObject { ["tenantId"] = "33333333-3333-3333-3333-333333333333" }
                }
            ]
        };

        var configMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        configMonitor.CurrentValue.Returns(config);

        _strategy = new SpecifiedSourceIdentifierStrategy(configMonitor);
        _context = new DefaultHttpContext();
        _options = new SpecifiedOptions { TenantId = null };
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

    [Fact] void should_succeed() => _succeeded.ShouldBeTrue();
    [Fact] void should_resolve_tenant_id_from_specified_configuration_strategy() =>
        _sourceIdentifier.ShouldEqual("33333333-3333-3333-3333-333333333333");
}
