// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Code;

/// <summary>
/// Asks the application to deliver a code and say who the address belongs to.
/// </summary>
public interface ICodeDelivery
{
    /// <summary>
    /// Posts a signed request to the application.
    /// </summary>
    /// <param name="settings">The provider's code settings.</param>
    /// <param name="request">What to deliver.</param>
    /// <returns>The stable subject the application named when it accepted the address and sent the code; otherwise <see langword="null"/>.</returns>
    Task<string?> Deliver(C.CodeSignIn settings, CodeRequest request);
}
