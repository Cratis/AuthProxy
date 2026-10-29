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
        var middleware = CreateMiddleware(ResolverReflectingConfirmation(), new MemoryCache(new MemoryCacheOptions()));

        var first = ContextFor("provider-a");
        await middleware.InvokeAsync(first);

        var second = ContextFor("provider-b");
        second.Request.Headers.Cookie = signed_selected_tenant_cookies.Value(first);
        await middleware.InvokeAsync(second);
    }

    [Fact] void should_revalidate_the_second_provider_tuple() => _handler.Calls.ShouldEqual(2);
}
