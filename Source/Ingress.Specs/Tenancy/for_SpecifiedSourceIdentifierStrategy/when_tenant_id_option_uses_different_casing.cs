// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.Tenancy.for_SpecifiedSourceIdentifierStrategy;

public class when_tenant_id_option_uses_different_casing : Specification
{
    SpecifiedSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    JsonObject _options;
    bool _succeeded;
    string _sourceIdentifier;

    void Establish()
    {
        _strategy = new SpecifiedSourceIdentifierStrategy();
        _context = new DefaultHttpContext();
        _options = new JsonObject { ["TENANTID"] = "33333333-3333-3333-3333-333333333333" };
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

    [Fact] void should_succeed() => _succeeded.ShouldBeTrue();
    [Fact] void should_return_the_configured_tenant_id() => _sourceIdentifier.ShouldEqual("33333333-3333-3333-3333-333333333333");
}