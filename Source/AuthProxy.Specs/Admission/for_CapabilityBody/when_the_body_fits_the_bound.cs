// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy.Admission.for_CapabilityBody;

/// <summary>
/// A capability within the bound is read whole, surrounding whitespace and all.
/// </summary>
public class when_the_body_fits_the_bound : Specification
{
    const string Capability = "a-presented-capability";

    string? _read;

    async Task Because()
    {
        await using var body = new MemoryStream(Encoding.UTF8.GetBytes($"  {Capability}\n"));
        _read = await CapabilityBody.TryRead(body, 4096, CancellationToken.None);
    }

    [Fact] void should_read_the_capability() => _read.ShouldEqual(Capability);
}
