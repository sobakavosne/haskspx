{-# LANGUAGE OverloadedStrings #-}

module SPXBindingsSpec
  ( spec
  ) where

import           Control.Monad   (replicateM)
import           Data.Bits       (xor)
import           Data.ByteString as BS (pack, replicate)
import qualified Data.ByteString as BS
import           SPXBindings     (cryptoSignBytes, cryptoSignPublicKeyBytes,
                                  cryptoSignSecretKeyBytes, cryptoSignSeedBytes,
                                  generateKeypair, sign, verify)
import           Test.Hspec      (Spec, describe, expectationFailure, it,
                                  shouldBe, shouldSatisfy)

spec :: Spec
spec = do
  describe "SPXBindings Sizes" $ do
    it "cryptoSignBytes returns correct size" testCryptoSignBytes
    it
      "cryptoSignSecretKeyBytes returns correct size"
      testCryptoSignSecretKeyBytes
    it
      "cryptoSignPublicKeyBytes returns correct size"
      testCryptoSignPublicKeyBytes
    it "cryptoSignSeedBytes returns correct size" testCryptoSignSeedBytes
  describe "SPXBindings Keypair and Signing" $ do
    it "Key generation produces valid keys" testKeyGeneration
    it "Signing and verifying a message works" testSignVerify
    it "Verifying with an invalid signature fails" testInvalidSignature
    it "Signing and verifying a long message works" testLongMessage

-- Utility function to handle errors in tests
handleIOError :: IO (Either String a) -> (a -> IO ()) -> IO ()
handleIOError action handler = do
  result <- action
  case result of
    Left err    -> expectationFailure err
    Right value -> handler value

testCryptoSignBytes :: IO ()
testCryptoSignBytes = do
  size <- cryptoSignBytes
  size `shouldSatisfy` (> 0)

testCryptoSignSecretKeyBytes :: IO ()
testCryptoSignSecretKeyBytes = do
  size <- cryptoSignSecretKeyBytes
  size `shouldSatisfy` (> 0)

testCryptoSignPublicKeyBytes :: IO ()
testCryptoSignPublicKeyBytes = do
  size <- cryptoSignPublicKeyBytes
  size `shouldSatisfy` (> 0)

testCryptoSignSeedBytes :: IO ()
testCryptoSignSeedBytes = do
  size <- cryptoSignSeedBytes
  size `shouldSatisfy` (> 0)

testKeyGeneration :: IO ()
testKeyGeneration = do
  seedBytes <- cryptoSignSeedBytes
  seed <- BS.pack <$> replicateM seedBytes (pure 0x00)
  handleIOError (generateKeypair seed) $ \(publicKey, secretKey) -> do
    publicKeyBytes <- cryptoSignPublicKeyBytes
    secretKeyBytes <- cryptoSignSecretKeyBytes
    BS.length publicKey `shouldBe` publicKeyBytes
    BS.length secretKey `shouldBe` secretKeyBytes

testSignVerify :: IO ()
testSignVerify = do
  seedBytes <- cryptoSignSeedBytes
  seed <- BS.pack <$> replicateM seedBytes (pure 0x01)
  handleIOError (generateKeypair seed) $ \(publicKey, secretKey) -> do
    let message = "Test message"
    handleIOError
      (sign (BS.pack $ map (fromIntegral . fromEnum) message) secretKey) $ \signature -> do
      handleIOError
        (verify
           (BS.pack $ map (fromIntegral . fromEnum) message)
           signature
           publicKey) $ \isValid -> isValid `shouldBe` True

testInvalidSignature :: IO ()
testInvalidSignature = do
  seedBytes <- cryptoSignSeedBytes
  seed <- BS.pack <$> replicateM seedBytes (pure 0x02)
  handleIOError (generateKeypair seed) $ \(publicKey, secretKey) -> do
    let message = "Invalid signature test"
    handleIOError
      (sign (BS.pack $ map (fromIntegral . fromEnum) message) secretKey) $ \signature -> do
      let invalidSignature = BS.map (`xor` 1) signature
      handleIOError
        (verify
           (BS.pack $ map (fromIntegral . fromEnum) message)
           invalidSignature
           publicKey) $ \isValid -> isValid `shouldBe` False

testLongMessage :: IO ()
testLongMessage = do
  seedBytes <- cryptoSignSeedBytes
  seed <- BS.pack <$> replicateM seedBytes (pure 0x03)
  handleIOError (generateKeypair seed) $ \(publicKey, secretKey) -> do
    let message = BS.replicate (2 ^ (20 :: Int)) 0x42 -- 1 MB message
    handleIOError (sign message secretKey) $ \signature -> do
      handleIOError (verify message signature publicKey) $ \isValid ->
        isValid `shouldBe` True
