// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Protects the entry transaction stored in the browser from disclosure and modification.
/// </summary>
public interface IEntryTransactionProtector
{
    /// <summary>
    /// Protects an entry transaction.
    /// </summary>
    /// <param name="transaction">The transaction to protect.</param>
    /// <returns>The protected value.</returns>
    string Protect(EntryTransaction transaction);

    /// <summary>
    /// Tries to recover a protected entry transaction.
    /// </summary>
    /// <param name="protectedTransaction">The protected value.</param>
    /// <param name="transaction">The recovered transaction when successful.</param>
    /// <returns><see langword="true"/> when the value is authentic; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Tampered, truncated and foreign-key-ring values are all simply not authentic. The caller has nothing
    /// to distinguish them by, which is the point: an attacker probing the cookie learns the same nothing
    /// from every attempt.
    /// </remarks>
    bool TryUnprotect(string protectedTransaction, out EntryTransaction transaction);
}
