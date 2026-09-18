{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | Focused unit tests for the fork-mode witnessing rule
-- ('Cardano.Ledger.Shelley.Rules.Utxow.validateNeededWitnessesForked') at
-- 'ShelleyEra'.
--
-- The god key is read once from @CARDANO_FORK_GOD_KEY@ at module load, so the
-- god-key cases are run in a child process (spawned by the parent) whose
-- environment has that variable set; the fork slot is supplied through
-- @CARDANO_FORK_SLOT@ in the same environment. The parent process, which has no
-- god key, covers the "no god key configured" case directly.
--
-- Past the fork slot the god branch of 'validateNeededWitnessesForked' ignores
-- its @CertState@ / @UTxO@ / @TxBody@ arguments, so those are passed as
-- 'undefined' there; the below-the-fork-slot (stock) case does use them, and is
-- given an empty transaction so that the needed-witness set is empty.
module Main (main) where

import Cardano.Crypto.Hash (hashFromBytes)
import Cardano.Ledger.BaseTypes (SlotNo (SlotNo))
import Cardano.Ledger.Core (TopTx, TxBody, mkBasicTxBody)
import Cardano.Ledger.Hashes (KeyHash (KeyHash), KeyRole (Witness))
import Cardano.Ledger.Shelley (ShelleyEra)
import Cardano.Ledger.Shelley.Rules (
  ShelleyUtxowPredFailure (MissingVKeyWitnessesUTXOW),
  validateNeededWitnessesForked,
 )
import Cardano.Ledger.State (CertState, UTxO (UTxO))
import Control.Monad (unless)
import qualified Data.ByteString as BS
import Data.Default (def)
import Data.Foldable (toList)
import qualified Data.Map.Strict as Map
import Data.Set (Set)
import qualified Data.Set as Set
import qualified Data.Set.NonEmpty as NonEmptySet
import Data.Word (Word8)
import System.Environment (getArgs, getEnvironment, getExecutablePath)
import System.Exit (ExitCode (ExitSuccess), exitFailure, exitSuccess)
import System.IO (hPutStrLn, stderr)
import System.Process (env, proc, readCreateProcessWithExitCode)
import Validation (Validation (Failure, Success))

-- | The 28-byte god key hash, matching @CARDANO_FORK_GOD_KEY@ set by the parent.
godKeyHex :: String
godKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabb"

godKey :: KeyHash Witness
godKey = mkKeyHash (BS.pack godKeyBytes)

godKeyBytes :: [Word8]
godKeyBytes =
  [ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd
  , 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb
  ]

-- | A witness key hash that is not the god key.
otherKey :: KeyHash Witness
otherKey = mkKeyHash (BS.replicate 28 0xEE)

mkKeyHash :: BS.ByteString -> KeyHash Witness
mkKeyHash bs = case hashFromBytes bs of
  Just h -> KeyHash h
  Nothing -> error "mkKeyHash: expected 28 bytes"

-- | Run the pure witnessing test and classify the outcome.
runForked ::
  SlotNo ->
  Set (KeyHash Witness) ->
  CertState ShelleyEra ->
  UTxO ShelleyEra ->
  TxBody TopTx ShelleyEra ->
  Either [ShelleyUtxowPredFailure ShelleyEra] ()
runForked slot wits certState utxo txBody =
  case validateNeededWitnessesForked slot wits certState utxo txBody of
    Success () -> Right ()
    Failure errs -> Left (toList errs)

-- | The rejection is the stock 'MissingVKeyWitnessesUTXOW' naming exactly the
-- god key, so unpatched clients can decode it.
isMissingGodKey :: [ShelleyUtxowPredFailure ShelleyEra] -> Bool
isMissingGodKey [MissingVKeyWitnessesUTXOW ws] = ws == NonEmptySet.singleton godKey
isMissingGodKey _ = False

check :: String -> Bool -> IO ()
check label cond = unless cond (die ("assertion failed: " ++ label))

die :: String -> IO a
die msg = hPutStrLn stderr msg >> exitFailure

-- | Assertions run with a god key configured (child process).
withGodKey :: IO ()
withGodKey = do
  -- Past the fork slot (100 < 150): the needed-witness set is {godKey}, so a
  -- tx witnessed only by another key is rejected with the stock
  -- 'MissingVKeyWitnessesUTXOW' naming the god key. The god
  -- branch does not touch the ledger-state arguments, so they are 'undefined'.
  let pastFork nonGod =
        runForked
          (SlotNo 150)
          (Set.singleton nonGod)
          (undefined :: CertState ShelleyEra)
          (undefined :: UTxO ShelleyEra)
          (undefined :: TxBody TopTx ShelleyEra)
  check "past fork: non-god witness rejected with MissingVKeyWitnessesUTXOW {godKey}" $
    case pastFork otherKey of
      Left errs -> isMissingGodKey errs
      Right () -> False
  -- Past the fork slot, the god key alone satisfies the witnessing rule.
  check "past fork: god key alone is accepted" $
    runForked
      (SlotNo 150)
      (Set.singleton godKey)
      (undefined :: CertState ShelleyEra)
      (undefined :: UTxO ShelleyEra)
      (undefined :: TxBody TopTx ShelleyEra)
      == Right ()
  -- At or below the fork slot (150 -> 50) the stock rule runs: an empty
  -- transaction needs no witnesses, so any provided witness is fine and no
  -- god-key requirement is imposed. This is byte-for-byte stock behaviour.
  check "below fork: stock behaviour (empty tx accepts any witness)" $
    runForked
      (SlotNo 50)
      (Set.singleton otherKey)
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
      (Set.singleton otherKey)
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
