// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.Tenancy.for_RouteSourceIdentifierStrategy;

public class when_path_matches_pattern : Specification
{
    RouteSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    RouteOptions _options;
    bool _succeeded;
    string _sourceIdentifier;

    void Establish()
    {
        _strategy = new RouteSourceIdentifierStrategy();
        _context = new DefaultHttpContext();

        // Pattern extracts tenant from /{tenant}/api pattern
        _options = new RouteOptions { Pattern = "/(?<sourceIdentifier>[^/]+)/" };
        _context.Request.Path = "/tenant-abc/api";
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

    [Fact] void should_succeed() => _succeeded.ShouldBeTrue();
    [Fact] void should_resolve_path_based_on_tenant_regex() => _sourceIdentifier.ShouldEqual("tenant-abc");
}