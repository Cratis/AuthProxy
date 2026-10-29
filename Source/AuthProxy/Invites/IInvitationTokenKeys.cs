// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.IdentityModel.Tokens;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Retrieves public signing keys bound to a configured invitation issuer and audience.
/// </summary>
public interface IInvitationTokenKeys
{
    /// <summary>
    /// Gets the last usable key set, retrieving or refreshing it when required.
    /// </summary>
    /// <param name="invite">The configured metadata URL, issuer and audience.</param>
    /// <param name="cancellationToken">Cancellation of the waiting request.</param>
    /// <param name="refresh">Whether an unknown key requires a rate-limited refresh.</param>
    /// <returns>Keys indexed by unique kid, or null when no usable set is available.</returns>
    Task<IReadOnlyDictionary<string, SecurityKey>?> GetSigningKeys(C.Invite invite, CancellationToken cancellationToken, bool refresh = false);
}
