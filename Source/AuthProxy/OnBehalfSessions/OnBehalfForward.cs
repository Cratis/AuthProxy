// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Represents the one request an on-behalf forward assertion is issued for.
/// </summary>
/// <param name="Service">The name of the configured service the request is sent to.</param>
/// <param name="Method">The HTTP method of the request as it is sent.</param>
/// <param name="Path">The absolute, percent-encoded path of the request as it is sent, without query string.</param>
/// <remarks>
/// The assertion states all three, so an application can tell an assertion lifted from one request, or sent to
/// another service, from the one AuthProxy issued for the request in front of it.
/// </remarks>
public sealed record OnBehalfForward(string Service, HttpMethod Method, string Path);
