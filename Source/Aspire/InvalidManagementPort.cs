// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire;

/// <summary>
/// The exception that is thrown when the declared management listener port is not a port number.
/// </summary>
/// <param name="port">The port that could not be used.</param>
/// <remarks>
/// Refused where the app host is built rather than carried to the proxy, so the mistake surfaces against
/// the line of code that made it. AuthProxy refuses the same value at startup — this only moves the
/// discovery earlier, to a compile-and-run of the app host instead of a deployment.
/// </remarks>
public class InvalidManagementPort(int port)
    : Exception($"'{port}' is not a management listener port. Name a free port between 1 and 65535, on which nothing else in the deployment listens.");
