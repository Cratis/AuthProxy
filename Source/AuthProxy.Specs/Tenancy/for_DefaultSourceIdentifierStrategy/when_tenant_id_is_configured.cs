// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_DefaultSourceIdentifierStrategy;

public class when_tenant_id_is_configured : Specification
{
    DefaultSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    DefaultOptions _options;
    bool _succeeded;
    string _sourceIdentifier;

    void Establish()
    {
        _strategy = new DefaultSourceIdentifierStrategy();
        _context = new DefaultHttpContext();
        _options = new DefaultOptions { TenantId = "11111111-1111-1111-1111-111111111111" };
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

    [Fact] void should_succeed() => _succeeded.ShouldBeTrue();
    [Fact] void should_return_the_configured_tenant_id() => _sourceIdentifier.ShouldEqual("11111111-1111-1111-1111-111111111111");
}
