{-# LANGUAGE DataKinds #-}

-- | Ledger-side adapter for the shared "fork mode" configuration.
--
-- The configuration itself (and every environment-variable read) lives in the
-- @cardano-fork-mode@ leaf package ("Cardano.ForkMode"). This module only
-- adapts the leaf package's raw 28-byte god-key hash into the ledger's
-- 'KeyHash' type, so the individual rule/script patches
-- ("Cardano.Ledger.Shelley.Rules.Utxow", "Cardano.Ledger.Shelley.Scripts" and
-- "Cardano.Ledger.Allegra.Scripts") do not each repeat the decoding.
--
-- When @CARDANO_FORK_GOD_KEY@ is set (@'Just' godKeyHash@) the witnessing rules
-- require exactly this key to witness a transaction, and the native-script
-- evaluators treat every @RequireSignature@ that this key has signed as
-- satisfied. The signature-verification path is left untouched, so the god
-- key's signature is still genuinely checked against the transaction body hash.
-- When unset (@'Nothing'@) behaviour is byte-for-byte identical to the unpatched
-- ledger. The slot gate on these behaviours lives at the patch sites (see
-- "Cardano.Ledger.Shelley.Rules.Utxow").
module Cardano.Ledger.Shelley.ForkMode (
  forkGodKeyHash,
) where

import qualified Cardano.ForkMode as ForkMode
import Cardano.Crypto.Hash (hashFromBytes)
import Cardano.Ledger.Hashes (KeyHash (..), KeyRole (Witness))

-- | The fork-mode \"god\" key hash as a ledger 'KeyHash', derived from
-- 'ForkMode.godKeyHash'. 'Nothing' when @CARDANO_FORK_GOD_KEY@ is unset, in
-- which case every fork-mode code path falls back to the unpatched behaviour.
-- A malformed value fails loudly (naming the variable) when first forced, inside
-- 'ForkMode.godKeyHash'.
forkGodKeyHash :: Maybe (KeyHash Witness)
forkGodKeyHash = do
  bytes <- ForkMode.godKeyHash
  KeyHash <$> hashFromBytes bytes
