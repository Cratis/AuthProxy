// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

/// <summary>
/// Prevents a request from leaving when the tenant it names cannot be told apart from a list of tenants.
/// </summary>
internal sealed class TenantHeaderIsAmbiguous : HttpRequestException
{
    /// <summary>Initializes a new instance of the <see cref="TenantHeaderIsAmbiguous"/> class.</summary>
    /// <param name="header">The name of the tenant header that was ambiguous.</param>
    internal TenantHeaderIsAmbiguous(string header) : base($"The tenant header '{header}' holds more than one value or a list of values and was not forwarded.")
    {
    }
}
