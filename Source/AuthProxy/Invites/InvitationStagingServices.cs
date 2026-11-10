// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// The collaborators needed to stage an invitation with the backend. Issuer and protector are
/// <see langword="null"/> when staging is unavailable.
/// </summary>
/// <param name="HttpClientFactory">The HTTP client factory used for the stage call.</param>
/// <param name="AttestationIssuer">The signed invitation-attestation issuer, or <see langword="null"/> when staging is unavailable.</param>
/// <param name="EntryStateProtector">The protected invitation-entry state service, or <see langword="null"/> when staging is unavailable.</param>
sealed record InvitationStagingServices(
    IHttpClientFactory HttpClientFactory,
    IInvitationAttestationIssuer? AttestationIssuer,
    IInvitationEntryStateProtector? EntryStateProtector);
