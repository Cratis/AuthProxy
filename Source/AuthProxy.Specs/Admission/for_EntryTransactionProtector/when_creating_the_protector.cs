// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Admission.for_EntryTransactionProtector;

/// <summary>
/// The purpose the entry transaction is sealed under is pinned to its exact literal, and to being a
/// different literal from every other protected cookie this proxy issues.
/// </summary>
/// <remarks>
/// One key ring protects every one of them, so the purpose string is the only thing that makes a value from
/// one cookie inauthentic in another. Nothing else in the codebase says so — a rename that happened to make
/// two purposes agree would leave both values mutually unprotectable with no error, no warning and no spec
/// noticing, and the pair that matters most is this one and the invitation entry state: their records
/// deserialize into each other's shape with the missing fields simply null.
/// </remarks>
public class when_creating_the_protector : Specification
{
    IDataProtectionProvider _provider;

    void Establish()
    {
        _provider = Substitute.For<IDataProtectionProvider>();
        _provider.CreateProtector(Arg.Any<string>()).Returns(Substitute.For<IDataProtector>());
    }

    void Because() => _ = new EntryTransactionProtector(_provider);

    [Fact]
    void should_seal_under_its_own_declared_purpose() =>
        _provider.Received(1).CreateProtector("Cratis.AuthProxy.EntryTransaction.v1");

    [Fact]
    void should_not_share_a_purpose_with_the_invitation_entry_state() =>
        string.Equals(EntryTransactionProtector.Purpose, InvitationEntryStateProtector.Purpose, StringComparison.Ordinal).ShouldBeFalse();
}
