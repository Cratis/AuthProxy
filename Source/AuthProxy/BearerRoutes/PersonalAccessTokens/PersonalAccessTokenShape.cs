// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.PersonalAccessTokens;

/// <summary>
/// The result of classifying a credential value.
/// </summary>
/// <param name="Kind">Where the value falls relative to the personal access token namespace.</param>
/// <param name="ResourceKey">The resource key the token names, only when <paramref name="Kind"/> is <see cref="PersonalAccessTokenKind.Canonical"/>.</param>
public readonly record struct PersonalAccessTokenShape(PersonalAccessTokenKind Kind, string? ResourceKey = null);
