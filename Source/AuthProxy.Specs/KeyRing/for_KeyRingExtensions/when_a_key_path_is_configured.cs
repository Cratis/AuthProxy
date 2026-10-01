// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection.Repositories;

namespace Cratis.AuthProxy.KeyRing.for_KeyRingExtensions;

/// <summary>
/// The released way of keeping a key ring — a directory named by <c language="text">DataProtectionKeysPath</c> — works as it did,
/// with none of the new settings present.
/// </summary>
public class when_a_key_path_is_configured : given.a_key_ring_configuration
{
    string _path;

    protected override IDictionary<string, string?> Settings => new Dictionary<string, string?>
    {
        [$"{Section}:DataProtectionKeysPath"] = _path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName()),
    };

    void Because() => Build();

    [Fact] void should_persist_to_the_directory() => _options.XmlRepository.ShouldBeOfExactType<FileSystemXmlRepository>();
    [Fact] void should_name_the_configured_directory() => ((FileSystemXmlRepository)_options.XmlRepository).Directory.FullName.TrimEnd(Path.DirectorySeparatorChar).ShouldEqual(Path.GetFullPath(_path).TrimEnd(Path.DirectorySeparatorChar));
}
