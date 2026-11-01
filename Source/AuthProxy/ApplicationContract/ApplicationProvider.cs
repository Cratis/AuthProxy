// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract;

/// <summary>
/// Represents one entry of the provider list: a provider kind and the identity the environment keys it by.
/// </summary>
public class ApplicationProvider
{
    /// <summary>
    /// Gets or sets the provider kind: <c language="text">EntraId</c>, <c language="text">GitHub</c>,
    /// <c language="text">Google</c>, <c language="text">Apple</c> or <c language="text">OpenId</c>.
    /// </summary>
    public string Kind { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the identity: the model's alias, otherwise the provider name. It is the provider's display
    /// name and the middle part of every environment key of the provider.
    /// </summary>
    public string Identity { get; set; } = string.Empty;
}
