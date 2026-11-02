// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Links;

/// <summary>
/// The values a request to start linking one provider carries.
/// </summary>
/// <param name="Provider">The scheme of the provider to link.</param>
/// <param name="Token">The one-time link token.</param>
/// <param name="ReturnUrl">The caller-supplied return URL, when one was given.</param>
internal record LinkRequest(string Provider, string Token, string? ReturnUrl);
