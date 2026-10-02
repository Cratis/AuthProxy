// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Represents a configured bearer-token issuer with its defaults applied.
/// </summary>
/// <param name="Issuer">The exact issuer identifier a token and the issuer metadata must both name.</param>
/// <param name="MetadataAddress">The address of the issuer's metadata document.</param>
/// <param name="TokenTypes">The accepted JWT <c language="text">typ</c> header values.</param>
/// <param name="RequireHttps">Whether the metadata and JWKS documents must be retrieved over HTTPS.</param>
public sealed record ResolvedBearerIssuer(string Issuer, string MetadataAddress, IReadOnlyList<string> TokenTypes, bool RequireHttps);
