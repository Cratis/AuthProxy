// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy.Admission.for_CapabilityBody;

/// <summary>
/// Presenting nothing is not presenting a capability.
/// </summary>
public class when_the_body_is_empty : Specification
{
    string? _read;

    async Task Because()
    {
        await using var body = new MemoryStream(Encoding.UTF8.GetBytes("   \n"));
        _read = await CapabilityBody.TryRead(body, 4096, CancellationToken.None);
    }

    [Fact] void should_read_nothing() => _read.ShouldBeNull();
}
