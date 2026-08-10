// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantSelectionMiddleware.given;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

/// <summary>
/// Specifies that tenant revalidation state is scoped to the complete canonical identity tuple.
/// </summary>
public class when_revalidating_a_selected_tenant_for_canonical_identities : a_canonical_tenant_selection_middleware
{
    async Task Because()
    {
        var tenantResolver = Substitute.For<ITenantResolver>();
        tenantResolver.TryResolve(Arg.Any<HttpContext>(), out Arg.Any<TenantResolutionResult>())
            .Returns(callInfo =>
            {
                callInfo[1] = new TenantResolutionResult(TenantId, C.TenantSourceIdentifierResolverType.Selection);
                return true;
            });
        var middleware = CreateMiddleware(tenantResolver, new MemoryCache(new MemoryCacheOptions()));

        await middleware.InvokeAsync(ContextFor("provider-a"));
        await middleware.InvokeAsync(ContextFor("provider-a"));
        await middleware.InvokeAsync(ContextFor("provider-b"));
    }

    [Fact] void should_reuse_the_exact_tuple_only() => _handler.Calls.ShouldEqual(2);
}
