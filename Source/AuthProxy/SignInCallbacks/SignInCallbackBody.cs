// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks;

/// <summary>
/// Represents the JSON body of a sign-in callback.
/// </summary>
/// <param name="Kind">Either <c language="text">SignedIn</c> or <c language="text">Returned</c>.</param>
/// <param name="Subject">The identifier of the user, as the application sees it in <c language="text">x-ms-client-principal-id</c>.</param>
/// <param name="Name">The display name of the user, or an empty string when the provider gave none.</param>
/// <param name="Email">The email address of the user, or an empty string when the provider gave none.</param>
/// <param name="IdentityProvider">The identity provider the user signed in with.</param>
/// <param name="Tenant">The tenant the user is acting in. Omitted from the JSON when none resolved.</param>
/// <param name="Occurred">When the sign-in or return happened, in UTC.</param>
public sealed record SignInCallbackBody(
    string Kind,
    string Subject,
    string Name,
    string Email,
    string IdentityProvider,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Tenant,
    DateTimeOffset Occurred);
