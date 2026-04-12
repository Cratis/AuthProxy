// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Ingress.Tenancy;

namespace Cratis.Ingress.Tenancy.for_ClaimSourceIdentifierStrategy;

public class when_falling_back_to_x_ms_client_principal_header : Specification
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
        
        // No claim on ClaimsPrincipal, so it falls back to x-ms-client-principal header
        }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

    [Fact] void should_fail() => Assert.False(_succeeded);
    [Fact] void should_return_empty_string() => Assert.Equal("", _sourceIdentifier);
}
