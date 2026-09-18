{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | Focused unit tests for the fork-mode witnessing rule
-- ('Cardano.Ledger.Shelley.Rules.Utxow.validateNeededWitnessesForked') at
-- 'ShelleyEra'.
--
-- The god key is read once from @CARDANO_FORK_GOD_KEY@ at module load, so the
-- god-key cases are run in a child process (spawned by the parent) whose
-- environment has that variable set to the hash of 'godKeyPair'; the fork slot
-- is supplied through @CARDANO_FORK_SLOT@ in the same environment. The parent
-- process, which has no god key, covers the "no god key configured" case
-- directly.
--
-- Past the fork slot the god branch of 'validateNeededWitnessesForked' ignores
-- its @CertState@ / @UTxO@ / @TxBody@ arguments, so those are passed as
-- 'undefined' there; the below-the-fork-slot (stock) case does use them, and is
-- given an empty transaction so that the needed-witness set is empty.
module Main (main) where

import Cardano.Crypto.Hash (hashToBytes)
import Cardano.Ledger.BaseTypes (SlotNo (SlotNo))
import Cardano.Ledger.Core (
  TopTx,
  TxBody,
  TxWits,
  addrTxWitsL,
  hashAnnotated,
  mkBasicTxBody,
  mkBasicTxWits,
 )
import Cardano.Ledger.Hashes (KeyHash (KeyHash), KeyRole (Witness))
import Cardano.Ledger.Keys (VKey, asWitness, hashKey)
import Cardano.Ledger.Shelley (ShelleyEra)
import Cardano.Ledger.Shelley.Rules (
  ShelleyUtxowPredFailure (InvalidWitnessesUTXOW, MissingVKeyWitnessesUTXOW),
  validateNeededWitnessesForked,
 )
import Cardano.Ledger.State (CertState, UTxO (UTxO))
import Control.Monad (unless)
import qualified Data.ByteString as BS
import Data.Default (def)
import Data.Foldable (toList)
import Data.Function ((&))
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.Set.NonEmpty as NonEmptySet
import Lens.Micro ((.~))
import Numeric (showHex)
import System.Environment (getArgs, getEnvironment, getExecutablePath)
import System.Exit (ExitCode (ExitSuccess), exitFailure, exitSuccess)
import System.IO (hPutStrLn, stderr)
import System.Process (env, proc, readCreateProcessWithExitCode)
import Test.Cardano.Ledger.Core.KeyPair (KeyPair (vKey), mkKeyPair, mkWitnessVKey)
import Validation (Validation (Failure, Success))

-- | The god key pair; the parent sets @CARDANO_FORK_GOD_KEY@ to its hash.
godKeyPair :: KeyPair Witness
godKeyPair = mkKeyPair 1

-- | A real key pair that is not the god key.
otherKeyPair :: KeyPair Witness
otherKeyPair = mkKeyPair 2

godKey :: KeyHash Witness
godKey = hashKey (vKey godKeyPair)

otherVKey :: VKey Witness
otherVKey = asWitness (vKey otherKeyPair)

-- | @CARDANO_FORK_GOD_KEY@ for the child: the god key hash as 56 hex characters.
godKeyHex :: String
godKeyHex = concatMap hexByte (BS.unpack (hashToBytes h))
  where
    KeyHash h = godKey
    hexByte w = let s = showHex w "" in if length s == 1 then '0' : s else s

-- | Transaction witnesses (VKey witnesses signing an empty body) from key pairs.
witsOf :: [KeyPair Witness] -> TxWits ShelleyEra
witsOf kps =
  mkBasicTxWits & addrTxWitsL .~ Set.fromList (mkWitnessVKey bodyHash <$> kps)
  where
    bodyHash = hashAnnotated (mkBasicTxBody :: TxBody TopTx ShelleyEra)

-- | Run the pure witnessing test and classify the outcome.
runForked ::
  SlotNo ->
  TxWits ShelleyEra ->
  CertState ShelleyEra ->
  UTxO ShelleyEra ->
  TxBody TopTx ShelleyEra ->
  Either [ShelleyUtxowPredFailure ShelleyEra] ()
runForked slot wits certState utxo txBody =
  case validateNeededWitnessesForked slot wits certState utxo txBody of
    Success () -> Right ()
    Failure errs -> Left (toList errs)

-- | Past the fork slot, where the god branch ignores the ledger-state arguments.
pastFork :: [KeyPair Witness] -> Either [ShelleyUtxowPredFailure ShelleyEra] ()
pastFork kps =
  runForked
    (SlotNo 150)
    (witsOf kps)
    (undefined :: CertState ShelleyEra)
    (undefined :: UTxO ShelleyEra)
    (undefined :: TxBody TopTx ShelleyEra)

-- | The stock 'MissingVKeyWitnessesUTXOW' naming exactly the god key.
isMissingGodKey :: ShelleyUtxowPredFailure ShelleyEra -> Bool
isMissingGodKey (MissingVKeyWitnessesUTXOW ws) = ws == NonEmptySet.singleton godKey
isMissingGodKey _ = False

-- | The stock 'InvalidWitnessesUTXOW' naming exactly the non-god key.
isInvalidOtherKey :: ShelleyUtxowPredFailure ShelleyEra -> Bool
isInvalidOtherKey (InvalidWitnessesUTXOW vks) = toList vks == [otherVKey]
isInvalidOtherKey _ = False

check :: String -> Bool -> IO ()
check label cond = unless cond (die ("assertion failed: " ++ label))

die :: String -> IO a
die msg = hPutStrLn stderr msg >> exitFailure

-- | Assertions run with a god key configured (child process). Every rejection
-- uses a stock predicate failure, so unpatched clients can decode it.
withGodKey :: IO ()
withGodKey = do
  -- Past the fork slot (100 < 150), a tx witnessed only by another key is
  -- missing the god key and carries a non-god witness.
  check "past fork: non-god witness alone rejected (missing god key + invalid other key)" $
    case pastFork [otherKeyPair] of
      Left [e1, e2] -> isMissingGodKey e1 && isInvalidOtherKey e2
      _ -> False
  -- The god key plus a real key is rejected: the god key is the sole permitted
  -- witness, and the extra key is reported with 'InvalidWitnessesUTXOW'.
  check "past fork: god key plus another key rejected with InvalidWitnessesUTXOW [other]" $
    case pastFork [godKeyPair, otherKeyPair] of
      Left [e] -> isInvalidOtherKey e
      _ -> False
  -- Past the fork slot, the god key alone satisfies the witnessing rule.
  check "past fork: god key alone is accepted" $
    pastFork [godKeyPair] == Right ()
  -- At or below the fork slot (150 -> 50) the stock rule runs: an empty
  -- transaction needs no witnesses, so any provided witness is fine and no
  -- god-key requirement is imposed. This is byte-for-byte stock behaviour.
  check "below fork: stock behaviour (empty tx accepts any witness)" $
    runForked
      (SlotNo 50)
      (witsOf [otherKeyPair])
      (def :: CertState ShelleyEra)
      (UTxO Map.empty)
      (mkBasicTxBody :: TxBody TopTx ShelleyEra)
      == Right ()
  putStrLn "PASS with-god-key"

-- | Assertion run without a god key (parent process): the rule is always stock,
-- so a non-god witness on an empty transaction is accepted even past the fork
-- slot.
withoutGodKey :: IO ()
withoutGodKey =
  check "no god key: stock behaviour even past the fork slot" $
    runForked
      (SlotNo 150)
      (witsOf [otherKeyPair])
      (def :: CertState ShelleyEra)
      (UTxO Map.empty)
      (mkBasicTxBody :: TxBody TopTx ShelleyEra)
      == Right ()

main :: IO ()
main = do
  args <- getArgs
  case args of
    ["with-god-key"] -> withGodKey
    _ -> do
      -- Parent: the no-god-key case runs here (this process has no god key set),
      -- then the god-key cases run in a child whose environment sets them.
      withoutGodKey
      self <- getExecutablePath
      baseEnv <- filter (not . isForkVar . fst) <$> getEnvironment
      let childEnv =
            baseEnv
              ++ [ ("CARDANO_FORK_GOD_KEY", godKeyHex)
                 , ("CARDANO_FORK_SLOT", "100")
                 ]
          cp = (proc self ["with-god-key"]) {env = Just childEnv}
      (code, out, err) <- readCreateProcessWithExitCode cp ""
      unless (null out) (putStr out)
      if code == ExitSuccess
        then do
          putStrLn "PASS no-god-key"
          putStrLn "cardano-ledger-shelley fork-mode: all cases passed"
          exitSuccess
        else do
          hPutStrLn stderr ("child failed: " ++ show code)
          unless (null err) (hPutStrLn stderr err)
          exitFailure
  where
    isForkVar name = take (length "CARDANO_FORK_") name == "CARDANO_FORK_"
