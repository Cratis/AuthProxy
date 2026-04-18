// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the configuration for all tenants, keyed by tenant ID.
/// </summary>
public class Tenants : Dictionary<string, Tenant>;
