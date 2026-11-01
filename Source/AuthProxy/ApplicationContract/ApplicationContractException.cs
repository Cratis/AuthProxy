// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract;

/// <summary>
/// Represents a failure to turn the application configuration contract into AuthProxy configuration.
/// </summary>
/// <remarks>
/// The message names the offending key, provider identity and environment. It never contains a value.
/// </remarks>
/// <param name="message">The description of what is wrong with the configuration.</param>
public class ApplicationContractException(string message) : Exception(message);
