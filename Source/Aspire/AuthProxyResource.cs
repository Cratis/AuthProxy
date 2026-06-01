// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire;

/// <summary>
/// Represents the AuthProxy container resource for use in Aspire application models.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="AuthProxyResource"/> class.
/// </remarks>
/// <param name="name">The resource name.</param>
public class AuthProxyResource(string name) : ContainerResource(name)
{
    /// <summary>The Docker Hub image name for AuthProxy.</summary>
    public const string ContainerImageName = "cratis/authproxy";

    /// <summary>The default Docker image tag (always resolves to the latest stable release).</summary>
    public const string ContainerImageTag = "latest";
}
