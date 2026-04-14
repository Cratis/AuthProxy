// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_ClaimSourceIdentifierStrategy;

public class when_claim_exists_on_claims_principal : Specification
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
        _options = new ClaimOptions { ClaimType = "http://schemas.microsoft.com/identity/claims/tenantid" };

        var identity = new ClaimsIdentity(
            [
                new Claim("http://schemas.microsoft.com/identity/claims/tenantid", "tenant-123")
            ],
            "aad");
        _context.User = new ClaimsPrincipal(identity);
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

    [Fact] void should_succeed() => Assert.True(_succeeded);
    [Fact] void should_return_the_claim_value() => Assert.Equal("tenant-123", _sourceIdentifier);
}
