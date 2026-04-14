// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress;

/// <summary>
/// Represents all the HTTP headers used by the ingress.
/// </summary>
public static class Headers
{
    /// <summary>
    /// Microsoft Identity Platform client principal (base64 encoded JSON).
    /// </summary>
    public const string Principal = "x-ms-client-principal";

    /// <summary>
    /// Microsoft Identity Platform client principal ID.
    /// </summary>
    public const string PrincipalId = "x-ms-client-principal-id";

    /// <summary>
    /// Microsoft Identity Platform client principal name.
    /// </summary>
    public const string PrincipalName = "x-ms-client-principal-name";

    /// <summary>
    /// Cratis tenant identifier.
    /// </summary>
    public const string TenantId = "Tenant-ID";

    /// <summary>
    /// Microservice identifier used to route requests to the appropriate microservice.
    /// </summary>
    public const string MicroserviceId = "Microservice-ID";
}
