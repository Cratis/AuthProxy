// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Configuration.for_Management;

/// <summary>
/// A deployment that never asked for a management listener must not end up with one. The section is
/// nullable rather than defaulted for exactly that reason: a default-constructed instance would be
/// indistinguishable from a deliberately empty one, and "no section" is the state that has to mean "change
/// nothing about how AuthProxy binds".
/// </summary>
public class when_the_section_is_absent : Specification
{
    C.AuthProxy _config;

    void Because() => _config = new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?> { ["PagesPath"] = "/tmp/pages" })
        .Build()
        .Get<C.AuthProxy>()!;

    [Fact] void should_leave_the_management_section_unset() => _config.Management.ShouldBeNull();
}
