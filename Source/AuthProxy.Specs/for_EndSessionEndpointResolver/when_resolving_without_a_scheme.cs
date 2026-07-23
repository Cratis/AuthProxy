// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Cratis.AuthProxy.for_EndSessionEndpointResolver;

public class when_resolving_without_a_scheme : Specification
{
    EndSessionEndpointResolver _resolver;
    string? _result;

    void Establish()
    {
        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication());

        _resolver = new EndSessionEndpointResolver(
            authConfig,
            Substitute.For<IOptionsMonitor<OpenIdConnectOptions>>(),
            Substitute.For<ILogger<EndSessionEndpointResolver>>());
    }

    async Task Because() => _result = await _resolver.Resolve(null, CancellationToken.None);

    [Fact] void should_not_resolve_an_endpoint() => _result.ShouldBeNull();
}
