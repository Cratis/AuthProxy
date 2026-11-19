// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress.for_DeniedPathNormalization;

public class when_other_path_characters_are_present
{
    [Theory]
    [InlineData("")]
    [InlineData("/x/ name")]
    [InlineData("/x/%20name")]
    [InlineData("/x/%")]
    [InlineData("/x/%25")]
    [InlineData("/x/a;b")]
    [InlineData("/x/é")]
    [InlineData("/x/%252F")]
    [InlineData("/x/%2e%2e")]
    [InlineData("/x/../internal")]
    public void should_leave_decoding_and_dot_segments_to_the_server(string path) =>
        DeniedPathNormalization.NormalizeSeparators(path).ShouldEqual(path);
}
