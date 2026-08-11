// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;

namespace Cratis.AuthProxy.Admission.for_CapabilityVerifier;

/// <summary>
/// The request that leaves this process names its three values exactly as the published verifier contract
/// says it will.
/// </summary>
/// <remarks>
/// A verifier is somebody else's service, written once against the documented body and deployed where
/// nothing here can rebuild it. The property names are therefore not an implementation detail of the
/// serializer — they are the contract, and the one line that chooses the naming policy can move all three at
/// once. Asserted against the literal names in the documentation rather than against a fixture that
/// serializes with the same options this code reads with, which would only ever agree with itself.
/// </remarks>
public class when_the_capability_is_carried_to_the_verifier : given.a_capability_verifier
{
    string[] _names;

    void Establish() => VerifierAnswering(async (request, cancellationToken) =>
    {
        using var document = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
        _names = document.RootElement.EnumerateObject().Select(_ => _.Name).ToArray();

        return Answer(true, _presentation.Transaction, _presentation.Challenge);
    });

    async Task Because() => _verification = await _verifier.Verify(_presentation, CancellationToken.None);

    [Fact] void should_publish_the_names_the_verifier_contract_documents() => _names.ShouldContainOnly("capability", "transaction", "challenge");
}
