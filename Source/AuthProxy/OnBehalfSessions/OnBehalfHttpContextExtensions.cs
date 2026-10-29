// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics.CodeAnalysis;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Extension methods for reading the on-behalf session active on a request.
/// </summary>
public static class OnBehalfHttpContextExtensions
{
    /// <summary>
    /// The <see cref="HttpContext.Items"/> key holding the active <see cref="OnBehalfContext"/>.
    /// </summary>
    public const string ItemKey = "Cratis.AuthProxy.OnBehalf";

    /// <summary>
    /// Gets the on-behalf session active on the request, if any.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="onBehalf">The active <see cref="OnBehalfContext"/>.</param>
    /// <returns><see langword="true"/> when the request acts on behalf of somebody; otherwise <see langword="false"/>.</returns>
    public static bool TryGetOnBehalf(this HttpContext context, [NotNullWhen(true)] out OnBehalfContext? onBehalf)
    {
        onBehalf = context.Items.TryGetValue(ItemKey, out var item) ? item as OnBehalfContext : null;
        return onBehalf is not null;
    }

    /// <summary>
    /// Marks the request as acting on behalf of somebody.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="onBehalf">The active <see cref="OnBehalfContext"/>.</param>
    public static void SetOnBehalf(this HttpContext context, OnBehalfContext onBehalf) => context.Items[ItemKey] = onBehalf;
}
