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
        var middleware = CreateMiddleware(ResolverReflectingConfirmation(), new MemoryCache(new MemoryCacheOptions()));

        await middleware.InvokeAsync(SelectedFor("provider-a"));
        await middleware.InvokeAsync(SelectedFor("provider-a"));
        await middleware.InvokeAsync(SelectedFor("provider-b"));
    }

    DefaultHttpContext SelectedFor(string provider)
    {
        var context = ContextFor(provider);
        signed_selected_tenant_cookies.Seed(context, TenantId);
        return context;
    }

    [Fact] void should_reuse_the_exact_tuple_only() => _handler.Calls.ShouldEqual(2);
}
