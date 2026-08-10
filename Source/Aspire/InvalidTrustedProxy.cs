// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire;

/// <summary>
/// The exception that is thrown when a declared trusted proxy is neither an IP address nor a CIDR range.
/// </summary>
/// <param name="value">The entry that could not be understood.</param>
/// <remarks>
/// Refused where the app host is built rather than carried to the proxy, so the mistake surfaces against the
/// line of code that made it. AuthProxy refuses the same value at startup — this only moves the discovery
/// earlier, to a compile-and-run of the app host instead of a deployment.
/// </remarks>
public class InvalidTrustedProxy(string value)
    : Exception($"'{value}' is not a trusted proxy. Declare a peer as '10.0.0.7' or '2001:db8::1', and a range as '10.0.0.0/8' or '2001:db8::/32'.");
