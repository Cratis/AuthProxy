// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Represents one call an introspection endpoint received.
/// </summary>
/// <param name="Method">The HTTP method.</param>
/// <param name="Path">The path.</param>
/// <param name="Query">The query string.</param>
/// <param name="ContentType">The content type.</param>
/// <param name="FormFields">The names of the form fields, ordered.</param>
/// <param name="Token">The <c language="text">token</c> field.</param>
/// <param name="Authorization">The <c language="text">Authorization</c> header.</param>
/// <param name="HeaderNames">The names of every header received.</param>
public sealed record CapturedIntrospection(
    string Method,
    string Path,
    string Query,
    string? ContentType,
    IReadOnlyList<string> FormFields,
    string Token,
    string Authorization,
    IReadOnlyList<string> HeaderNames);
