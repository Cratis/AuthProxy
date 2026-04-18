// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_SpecifiedSourceIdentifierStrategy;

public class when_configured_tenant_id_is_whitespace : Specification
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
                    Strategy = C.TenantSourceIdentifierResolverType.Specified,
                    Options = new JsonObject { ["tenantId"] = "   " }
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

    [Fact] void should_fail() => _succeeded.ShouldBeFalse();
    [Fact] void should_return_empty_source_identifier() => _sourceIdentifier.ShouldEqual(string.Empty);
}
