// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Ingress.Tenancy;

namespace Cratis.Ingress.Tenancy.for_SpecifiedSourceIdentifierStrategy;

public class when_tenant_id_is_resolved_from_configuration : Specification
{
    SpecifiedSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    SpecifiedOptions _options;
    bool _succeeded;
    string _sourceIdentifier;

    void Establish()
     {
        _strategy = new SpecifiedSourceIdentifierStrategy();
        _context = new DefaultHttpContext();
        _options = new SpecifiedOptions { TenantId = "11111111-1111-1111-1111-111111111111" };
     }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

 [Fact] void should_succeed() => _succeeded.ShouldBeTrue();
 [Fact] void should_resolve_tenant_id_from_options() => _sourceIdentifier.ShouldEqual("11111111-1111-1111-1111-111111111111");
}