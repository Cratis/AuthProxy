// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantSelectionMiddleware.given;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

/// <summary>
/// Specifies that automatic single-tenant selection does not authorize another canonical provider tuple.
/// </summary>
public class when_a_single_tenant_was_selected_for_another_canonical_provider : a_canonical_tenant_selection_middleware
{
    async Task Because()
    {
        var calls = 0;
        var tenantResolver = Substitute.For<ITenantResolver>();
        tenantResolver.TryResolve(Arg.Any<HttpContext>(), out Arg.Any<TenantResolutionResult>())
            .Returns(callInfo =>
            {
                calls++;
                callInfo[1] = new TenantResolutionResult(TenantId, C.TenantSourceIdentifierResolverType.Selection);
                return calls > 1;
            });
        var middleware = CreateMiddleware(tenantResolver, new MemoryCache(new MemoryCacheOptions()));

        await middleware.InvokeAsync(ContextFor("provider-a"));
        await middleware.InvokeAsync(ContextFor("provider-b"));
    }

    [Fact] void should_revalidate_the_second_provider_tuple() => _handler.Calls.ShouldEqual(2);
}
