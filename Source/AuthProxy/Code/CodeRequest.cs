// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Code;

/// <summary>
/// What AuthProxy tells the application when a person asks for a code.
/// </summary>
/// <param name="Email">The address the code is for.</param>
/// <param name="Code">The code the application delivers by e-mail.</param>
/// <param name="Purpose">Either <c language="text">signIn</c> or <c language="text">invitation</c>.</param>
/// <param name="InvitationId">The invitation being answered, for the invitation purpose.</param>
/// <param name="Locale">The person's preferred language, from the browser.</param>
/// <param name="ExpiresAt">When the code stops being usable.</param>
public sealed record CodeRequest(
    string Email,
    string Code,
    string Purpose,
    string? InvitationId,
    string Locale,
    DateTimeOffset ExpiresAt);
