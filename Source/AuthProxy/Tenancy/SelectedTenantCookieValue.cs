// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// The outcome of reading the selected-tenant cookie.
/// </summary>
/// <param name="State">What the cookie holds.</param>
/// <param name="TenantId">The tenant the cookie names; empty unless the state is <see cref="SelectedTenantCookieState.Bound"/> or <see cref="SelectedTenantCookieState.Legacy"/>.</param>
public sealed record SelectedTenantCookieValue(SelectedTenantCookieState State, string TenantId)
{
    /// <summary>
    /// Gets a value for a request that carries no cookie.
    /// </summary>
    public static readonly SelectedTenantCookieValue None = new(SelectedTenantCookieState.None, string.Empty);

    /// <summary>
    /// Gets a value for a cookie that cannot be trusted.
    /// </summary>
    public static readonly SelectedTenantCookieValue Invalid = new(SelectedTenantCookieState.Invalid, string.Empty);
}
