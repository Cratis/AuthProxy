// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Ingress.Tenancy;

namespace Cratis.Ingress.Tenancy.for_HostSourceIdentifierStrategy;

public class when_host_is_present : Specification
{
    HostSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    object _options;
    bool _succeeded;
    string _sourceIdentifier;

    void Establish()
    {
        _strategy = new HostSourceIdentifierStrategy();
        _context = new DefaultHttpContext();
        _options = null;
        _context.Request.Host = new HostString("test.example.net");
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

    [Fact] void should_succeed() => _succeeded.ShouldBeTrue();
    [Fact] void should_resolve_host() => _sourceIdentifier.ShouldEqual("test.example.net");
}