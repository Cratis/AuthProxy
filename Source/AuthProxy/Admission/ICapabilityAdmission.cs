// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Turns a presented capability into an entry, or into nothing.
/// </summary>
public interface ICapabilityAdmission
{
    /// <summary>
    /// Reads the presentation on the current request, has it verified, and issues the entry transaction
    /// when it admits.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns><see langword="true"/> when the caller was admitted and answered; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Answering <see langword="false"/> leaves the response untouched so the caller receives the same
    /// refusal every other unadmitted request does — the wrong method, an oversized body, a malformed
    /// value, a refused one and a verifier that never answered are all one outcome from here.
    /// </remarks>
    Task<bool> TryAdmit(HttpContext context, C.AuthProxy config);
}
