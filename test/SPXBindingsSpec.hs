{-# LANGUAGE InstanceSigs      #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module SPXBindingsSpec
  ( spec
  ) where

import           Data.Bits       (xor)
import           Data.ByteString (ByteString, unpack)
import qualified Data.ByteString as BS
import           Data.Maybe      (fromJust)
import           GHC.IO.Unsafe   (unsafePerformIO)
import           SPXBindings     (cryptoSignBytes, cryptoSignPublicKeyBytes,
                                  cryptoSignSecretKeyBytes, cryptoSignSeedBytes,
                                  generateKeypair, sign, verify)
import           Test.Hspec      (Spec, describe, it, shouldBe)
import           Test.QuickCheck (Arbitrary (arbitrary), Gen,
                                  Testable (property), vectorOf, (==>))

instance Arbitrary ByteString where
  arbitrary :: Gen ByteString
  arbitrary = do
    let seedSize = unsafePerformIO cryptoSignSeedBytes
    bytes <- vectorOf seedSize arbitrary
    return $ BS.pack bytes

spec :: Spec
spec =
  describe "SPHINCS+ Binding Tests" $ do
    it "Returns correct sizes for keys and signature" $ do
      let sizes = (fromJust . lookup activeParamSet) expectedSizes
      pkSize <- cryptoSignPublicKeyBytes
      skSize <- cryptoSignSecretKeyBytes
      sigSize <- cryptoSignBytes
      seedSize <- cryptoSignSeedBytes
      pkSize `shouldBe` head sizes
      skSize `shouldBe` sizes !! 1
      sigSize `shouldBe` sizes !! 2
      seedSize `shouldBe` 48
    it "Generates valid keypair" $
      property $ \seed ->
        BS.length seed ==
        unsafePerformIO cryptoSignSeedBytes ==>
        case unsafePerformIO $ generateKeypair seed of
          Left _ -> False
          Right (pub, sec) ->
            BS.length pub == unsafePerformIO cryptoSignPublicKeyBytes &&
            BS.length sec == unsafePerformIO cryptoSignSecretKeyBytes
    it "Signs and verifies a message correctly" $
      property $ \seed message ->
        let validSeed = BS.length seed == unsafePerformIO cryptoSignSeedBytes
            validMessage = BS.length message > 0
         in validSeed &&
            validMessage ==>
            case unsafePerformIO $ generateKeypair seed of
              Left _ -> False
              Right (pub, sec) ->
                case unsafePerformIO $ sign message sec of
                  Left _ -> False
                  Right sig ->
                    unsafePerformIO (verify message sig pub) == Right True
    it "Fails to verify corrupted signatures" $ do
      seed <- randomSeed
      case unsafePerformIO $ generateKeypair seed of
        Left _ -> False `shouldBe` True
        Right (pub, sec) -> do
          let message = BS.pack [1, 2, 3, 4]
          case unsafePerformIO $ sign message sec of
            Left _ -> False `shouldBe` True
            Right sig -> do
              let corruptedSig = BS.pack $ map (`xor` 0xFF) (unpack sig)
              valid <- verify message corruptedSig pub
              valid `shouldBe` Right False
    it "Handles large messages" $ do
      seed <- randomSeed
      case unsafePerformIO $ generateKeypair seed of
        Left _ -> False `shouldBe` True
        Right (pub, sec) -> do
          let message = BS.replicate (2 ^ (20 :: Integer)) 0xAA
          case unsafePerformIO $ sign message sec of
            Left _ -> False `shouldBe` True
            Right sig -> do
              result <- verify message sig pub
              result `shouldBe` Right True
    it "Fails on invalid seed length" $ do
      let seed = BS.replicate 5 0xFF -- Incorrect length
      let result = unsafePerformIO $ generateKeypair seed
      result `shouldBe` Left "Invalid seed length"
    it "Fails on invalid signature length" $ do
      seed <- randomSeed
      case unsafePerformIO $ generateKeypair seed of
        Left _ -> False `shouldBe` True
        Right (pub, _) -> do
          let message = BS.pack [1, 2, 3, 4]
          let sig = BS.pack [0x01, 0x02] -- Incorrect length
          valid <- verify message sig pub
          valid `shouldBe` Right False
    it "Verifies expected sizes for parameter sets" $ do
      let sizes = (fromJust . lookup activeParamSet) expectedSizes
      pkSize <- cryptoSignPublicKeyBytes
      skSize <- cryptoSignSecretKeyBytes
      sigSize <- cryptoSignBytes
      pkSize `shouldBe` head sizes
      skSize `shouldBe` sizes !! 1
      sigSize `shouldBe` sizes !! 2

activeParamSet :: String
activeParamSet = "shake_128f"

expectedSizes :: [(String, [Int])]
expectedSizes =
  [ ("shake_128s", [32, 64, 7856])
  , ("shake_128f", [32, 64, 17088])
  , ("shake_192s", [48, 96, 16224])
  , ("shake_192f", [48, 96, 35664])
  , ("shake_256s", [64, 128, 29792])
  , ("shake_256f", [64, 128, 49856])
  , ("sha2_128s", [32, 64, 7856])
  , ("sha2_128f", [32, 64, 17088])
  ]

randomSeed :: IO ByteString
randomSeed = do
  seedSize <- cryptoSignSeedBytes
  return $ BS.replicate seedSize 0xAA
