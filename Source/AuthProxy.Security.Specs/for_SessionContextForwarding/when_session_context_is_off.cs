// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Security.for_SessionContextForwarding;

public class when_session_context_is_off : given.a_session_context
{
    [Fact]
    public async Task should_preserve_the_previous_envelope_bytes()
    {
        await using var harness = new SessionContextHarness(false);
        var observed = await Forward(harness, await harness.SignIn());
        const string expected = "{\"identityProvider\":\"AuthenticationTypes.Federation\",\"userId\":\"session-user\",\"userDetails\":\"user@example.test\",\"userRoles\":[\"anonymous\",\"authenticated\"],\"claims\":[{\"typ\":\"sub\",\"val\":\"session-user\"},{\"typ\":\"email\",\"val\":\"user@example.test\"}]}";
        Assert.Equal(Convert.ToBase64String(Encoding.UTF8.GetBytes(expected)), observed.Value(Headers.Principal));
        Assert.DoesNotContain(Claims(observed), claim => SessionClaims.IsForwardedSessionContext(claim!["typ"]!.GetValue<string>()));
    }
}
