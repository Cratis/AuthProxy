// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_ClientPrincipalExtensions;

public class when_building_from_unauthenticated_context : Specification
{
    DefaultHttpContext _context;
    ClientPrincipal? _result;

    void Establish() => _context = new DefaultHttpContext();

    void Because() => _result = _context.BuildClientPrincipal();

    [Fact] void should_return_null() => Assert.Null(_result);
}
