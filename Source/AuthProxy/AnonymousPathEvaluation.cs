// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

/// <summary>
/// Represents the outcome of evaluating a single declared anonymous path entry.
/// </summary>
/// <param name="Declared">The entry exactly as it was declared in configuration.</param>
/// <param name="Prefix">The normalized prefix when the entry is usable; otherwise empty.</param>
/// <param name="Rejection">Why the entry was refused, or <see cref="AnonymousPathRejection.None"/>.</param>
/// <remarks>
/// <paramref name="Declared"/> is kept alongside the result so a refusal can be reported in the operator's
/// own words — the string they put in configuration — rather than in whatever it normalized to before it
/// was thrown away.
/// </remarks>
public sealed record AnonymousPathEvaluation(string Declared, string Prefix, AnonymousPathRejection Rejection)
{
    /// <summary>
    /// Gets a value indicating whether the entry survived evaluation and can be served anonymously.
    /// </summary>
    public bool IsUsable => Rejection == AnonymousPathRejection.None;

    /// <summary>
    /// Gets the declared entry rendered safe to write to a log.
    /// </summary>
    /// <remarks>
    /// The entry is reported precisely because it was refused, and a control character is one of the
    /// reasons it can be refused — so the value most in need of reporting is the one carrying a newline
    /// that would forge a second log line, or a terminal escape sequence. Control characters are replaced
    /// and the value truncated, so a refusal can always be reported without the refused text deciding how
    /// it is displayed.
    /// </remarks>
    public string DeclaredForDisplay => Sanitize(Declared);

    static string Sanitize(string value)
    {
        const int maxLength = 120;

        var truncated = value.Length > maxLength ? value[..maxLength] : value;

        return string.Create(truncated.Length, truncated, static (span, source) =>
        {
            for (var i = 0; i < source.Length; i++)
            {
                span[i] = char.IsControl(source[i]) ? '_' : source[i];
            }
        });
    }
}
