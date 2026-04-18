// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_SubHostSourceIdentifierStrategy;

public class when_subhost_matches_parent_host : Specification
{
    SubHostSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    SubHostOptions _options;
    bool _succeeded;
    string _sourceIdentifier;

    void Establish()
    {
        _strategy = new SubHostSourceIdentifierStrategy();
        _context = new DefaultHttpContext();
        _context.Request.Host = new HostString("acme.example.com");
        _options = new SubHostOptions { ParentHost = "example.com" };
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

    [Fact] void should_succeed() => _succeeded.ShouldBeTrue();
    [Fact] void should_resolve_the_subhost_as_tenant_id() => _sourceIdentifier.ShouldEqual("acme");
}
