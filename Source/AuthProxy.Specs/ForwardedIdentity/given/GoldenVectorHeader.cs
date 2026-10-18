// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.given;

/// <summary>
/// One header of the golden-vector request.
/// </summary>
/// <param name="Name">The header name.</param>
/// <param name="Value">The header value, as transmitted.</param>
public sealed record GoldenVectorHeader(string Name, string Value);
