// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Code;

/// <summary>
/// Keeps code sign-in state as small files in a directory, which is meant to be a mounted volume.
/// </summary>
/// <remarks>
/// Every read-modify-write opens the file exclusively, so a code is consumed at most once and attempts are counted
/// exactly even with concurrent requests or replicas sharing the volume.
/// </remarks>
/// <param name="path">The directory holding the state.</param>
/// <param name="timeProvider">The clock.</param>
public sealed class FileCodeChallengeStore(string path, TimeProvider timeProvider) : ICodeChallengeStore
{
    const int LockAttempts = 100;
    static readonly TimeSpan _lockDelay = TimeSpan.FromMilliseconds(20);
    static readonly TimeSpan _sweepInterval = TimeSpan.FromMinutes(1);
    static readonly TimeSpan _retention = TimeSpan.FromHours(2);

    readonly Lock _sweepLock = new();
    DateTimeOffset _lastSweep = DateTimeOffset.MinValue;

    /// <inheritdoc/>
    public async Task Create(CodeChallenge challenge)
    {
        Directory.CreateDirectory(path);
        Sweep();
        await using var stream = new FileStream(ChallengePath(challenge.Id), FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await JsonSerializer.SerializeAsync(stream, challenge);
    }

    /// <inheritdoc/>
    public async Task<CodeVerification> Verify(string scheme, string id, string code, int maxAttempts)
    {
        if (!IsIdentifier(id))
        {
            return new(CodeVerificationOutcome.Refused);
        }

        var file = ChallengePath(id);
        await using var stream = await OpenExclusive(file, FileMode.Open);
        if (stream is null)
        {
            return new(CodeVerificationOutcome.Refused);
        }

        var challenge = await JsonSerializer.DeserializeAsync<CodeChallenge>(stream);
        if (challenge?.Consumed is not false
            || challenge.Scheme != scheme
            || challenge.ExpiresAt <= timeProvider.GetUtcNow()
            || challenge.Attempts >= maxAttempts)
        {
            return new(CodeVerificationOutcome.Refused);
        }

        // A challenge made for an address the application does not accept carries no subject and is counted like any other,
        // so a wrong code and a code for an unknown address cannot be told apart.
        if (CodeHash.Matches(challenge.Salt, challenge.Hash, code) && challenge.Subject.Length > 0)
        {
            var used = challenge with { Consumed = true, ExpiresAt = timeProvider.GetUtcNow() };
            await Rewrite(stream, used);
            return new(CodeVerificationOutcome.Verified, challenge);
        }

        await Rewrite(stream, challenge with { Attempts = challenge.Attempts + 1 });
        return challenge.Attempts + 1 >= maxAttempts
            ? new(CodeVerificationOutcome.Refused)
            : new(CodeVerificationOutcome.Wrong);
    }

    /// <inheritdoc/>
    public async Task<bool> TryCount(string key, int limit, TimeSpan window)
    {
        Directory.CreateDirectory(path);
        var now = timeProvider.GetUtcNow();
        await using var stream = await OpenExclusive(CounterPath(key), FileMode.OpenOrCreate)
            ?? throw new IOException("The request counter could not be locked.");

        var stamps = stream.Length == 0
            ? []
            : await JsonSerializer.DeserializeAsync<List<DateTimeOffset>>(stream) ?? [];
        stamps.RemoveAll(stamp => stamp <= now - window);
        var allowed = stamps.Count < limit;
        if (allowed)
        {
            stamps.Add(now);
        }

        await Rewrite(stream, stamps);
        return allowed;
    }

    static bool IsIdentifier(string id) =>
        id.Length is > 0 and <= 128 && id.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    static async Task Rewrite<T>(FileStream stream, T value)
    {
        stream.SetLength(0);
        await JsonSerializer.SerializeAsync(stream, value);
        await stream.FlushAsync();
    }

    static async Task<FileStream?> OpenExclusive(string file, FileMode mode)
    {
        for (var attempt = 0; attempt < LockAttempts; attempt++)
        {
            try
            {
                return new FileStream(file, mode, FileAccess.ReadWrite, FileShare.None);
            }
            catch (FileNotFoundException)
            {
                return null;
            }
            catch (DirectoryNotFoundException)
            {
                return null;
            }
            catch (IOException) when (File.Exists(file))
            {
                await Task.Delay(_lockDelay);
            }
        }

        return null;
    }

    string ChallengePath(string id) => Path.Combine(path, $"challenge-{id}.json");

    string CounterPath(string key) =>
        Path.Combine(path, $"counter-{Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(key)))}.json");

    void Sweep()
    {
        var now = timeProvider.GetUtcNow();
        lock (_sweepLock)
        {
            if (now - _lastSweep < _sweepInterval)
            {
                return;
            }

            _lastSweep = now;
        }

        foreach (var file in Directory.EnumerateFiles(path, "*.json"))
        {
            try
            {
                if (now - new DateTimeOffset(File.GetLastWriteTimeUtc(file)) > _retention)
                {
                    File.Delete(file);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
