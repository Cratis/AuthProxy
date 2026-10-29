// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_ClaimSourceIdentifierStrategy;

public class when_only_the_inbound_principal_header_carries_the_claim : Specification
{
    ClaimSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    ClaimOptions _options;
    bool _succeeded;
    string _sourceIdentifier;

    void Establish()
    {
        _strategy = new ClaimSourceIdentifierStrategy();
        _context = new DefaultHttpContext();
        _options = new ClaimOptions { ClaimType = "tenant_claim" };

        var principal = new ClientPrincipal
        {
            Claims =
            [
                new ClientPrincipalClaim { Type = "tenant_claim", Value = "tenant-from-header" }
            ]
        };

        _context.Request.Headers[Headers.Principal] = principal.ToBase64();
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

    [Fact] void should_not_resolve() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_return_a_value() => _sourceIdentifier.ShouldEqual(string.Empty);
}
