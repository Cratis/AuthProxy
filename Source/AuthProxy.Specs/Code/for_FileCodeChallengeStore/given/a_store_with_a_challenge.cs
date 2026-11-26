// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Code.for_FileCodeChallengeStore.given;

public class a_store_with_a_challenge : Specification, IDisposable
{
    protected const string Scheme = "code";
    protected const string TheCode = "123456";
    protected const int MaxAttempts = 3;

    protected string _path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
    protected FileCodeChallengeStore _store = null!;
    protected Authentication.for_ClientCredentialsTokenProtector.given.ManualTime _time = new(DateTimeOffset.Parse("2026-11-20T10:00:00Z"));
    protected CodeChallenge _challenge = null!;

    void Establish()
    {
        _store = new FileCodeChallengeStore(_path, _time);
        var salt = CodeHash.NewSalt();
        _challenge = new CodeChallenge("challenge-1", Scheme, "a@example.com", "user-1", salt, CodeHash.Compute(salt, TheCode), _time.GetUtcNow().AddMinutes(10), 0, false);
        _store.Create(_challenge).GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        if (Directory.Exists(_path))
        {
            Directory.Delete(_path, recursive: true);
        }

        GC.SuppressFinalize(this);
    }
}
