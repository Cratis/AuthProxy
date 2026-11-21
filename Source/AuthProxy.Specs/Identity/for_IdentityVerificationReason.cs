// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Which reasons mean the service could not be asked, and which mean it answered no.
/// </summary>
public class for_IdentityVerificationReason
{
    [Theory]
    [InlineData(IdentityVerificationReason.TimedOut)]
    [InlineData(IdentityVerificationReason.TransportFailure)]
    [InlineData(IdentityVerificationReason.UnsuccessfulStatusCode)]
    [InlineData(IdentityVerificationReason.EmptyResponse)]
    [InlineData(IdentityVerificationReason.UnreadableResponse)]
    void should_treat_an_unanswered_question_as_unavailable(IdentityVerificationReason reason) => reason.IsUnavailable().ShouldBeTrue();

    [Theory]
    [InlineData(IdentityVerificationReason.Forbidden)]
    [InlineData(IdentityVerificationReason.NotAuthorized)]
    [InlineData(IdentityVerificationReason.ConflictingVerdict)]
    [InlineData(IdentityVerificationReason.NoVerdict)]
    void should_treat_a_refusal_as_a_refusal(IdentityVerificationReason reason) => reason.IsUnavailable().ShouldBeFalse();
}
