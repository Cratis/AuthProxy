// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Ingress.Tenancy;

namespace Cratis.Ingress.Tenancy.for_SpecifiedSourceIdentifierStrategy;

public class when_tenant_id_is_not_configured : Specification
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
        _options = new SpecifiedOptions { TenantId = null };
         }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

      [Fact] void should_fail() => Assert.False(_succeeded);
      [Fact] void should_return_empty_string() => Assert.Equal("", _sourceIdentifier);
}
