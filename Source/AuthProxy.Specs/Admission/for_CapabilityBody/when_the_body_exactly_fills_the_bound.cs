// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy.Admission.for_CapabilityBody;

/// <summary>
/// The bound is inclusive. A capability of exactly the declared size is a capability, not an overrun.
/// </summary>
public class when_the_body_exactly_fills_the_bound : Specification
{
    const int Bound = 32;

    string? _read;

    async Task Because()
    {
        await using var body = new MemoryStream(Encoding.UTF8.GetBytes(new string('a', Bound)));
        _read = await CapabilityBody.TryRead(body, Bound, CancellationToken.None);
    }

    [Fact] void should_read_the_capability() => _read.ShouldEqual(new string('a', Bound));
}
