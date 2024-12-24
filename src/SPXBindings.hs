{-# LANGUAGE ForeignFunctionInterface #-}

module SPXBindings
  ( cryptoSignBytes
  , cryptoSignSecretKeyBytes
  , cryptoSignPublicKeyBytes
  , cryptoSignSeedBytes
  , sign
  , verify
  , generateKeypair
  ) where

import           Data.ByteString (ByteString, packCStringLen, useAsCStringLen)
import qualified Data.ByteString as BS
import           Foreign         (Ptr, Storable (peek, sizeOf), castPtr,
                                  mallocBytes)
import           Foreign.C       (CInt (..), CSize (..), CUChar)

-- Foreign imports for the SPHINCS+ library functions
foreign import ccall "crypto_sign_bytes" c_crypto_sign_bytes :: IO CSize

foreign import ccall "crypto_sign_secretkeybytes" c_crypto_sign_secretkeybytes
  :: IO CSize

foreign import ccall "crypto_sign_publickeybytes" c_crypto_sign_publickeybytes
  :: IO CSize

foreign import ccall "crypto_sign_seedbytes" c_crypto_sign_seedbytes :: IO CSize

foreign import ccall "crypto_sign" c_crypto_sign
  :: Ptr CUChar ->
  Ptr CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> IO CInt

foreign import ccall "crypto_sign_open" c_crypto_sign_open
  :: Ptr CUChar ->
  Ptr CSize -> Ptr CUChar -> CSize -> Ptr CUChar -> IO CInt

foreign import ccall "crypto_sign_seed_keypair" c_crypto_sign_seed_keypair
  :: Ptr CUChar -> Ptr CUChar -> Ptr CUChar -> IO ()

-- Returns the size of the signature in bytes
cryptoSignBytes :: IO Int
cryptoSignBytes = fromIntegral <$> c_crypto_sign_bytes

-- Returns the size of the secret key in bytes
cryptoSignSecretKeyBytes :: IO Int
cryptoSignSecretKeyBytes = fromIntegral <$> c_crypto_sign_secretkeybytes

-- Returns the size of the public key in bytes
cryptoSignPublicKeyBytes :: IO Int
cryptoSignPublicKeyBytes = fromIntegral <$> c_crypto_sign_publickeybytes

-- Returns the size of the seed in bytes
cryptoSignSeedBytes :: IO Int
cryptoSignSeedBytes = fromIntegral <$> c_crypto_sign_seedbytes

-- Signs a message using the secret key
sign :: ByteString -> ByteString -> IO (Either String ByteString)
sign message secretKey = do
  secretKeyBytes <- cryptoSignSecretKeyBytes
  sigBytes <- cryptoSignBytes
  if BS.length secretKey /= secretKeyBytes
    then return $ Left "Invalid secret key length"
    else useAsCStringLen message $ \(msgPtr, msgLen) ->
           useAsCStringLen secretKey $ \(skPtr, _) -> do
             sig <- mallocBytes (msgLen + sigBytes)
             sigLen <- mallocBytes (sizeOf (undefined :: CSize))
             result <-
               c_crypto_sign
                 (castPtr sig)
                 sigLen
                 (castPtr msgPtr)
                 (fromIntegral msgLen)
                 (castPtr skPtr)
             if result /= 0
               then return $ Left "Signing failed"
               else do
                 len <- peek sigLen
                 let actualLen = fromIntegral len
                 if actualLen /= (sigBytes + msgLen)
                   then return $ Left "Signature length mismatch"
                   else do
                     fullSig <- BS.packCStringLen (sig, actualLen) -- IO ByteString
                     let sigOnly = BS.take sigBytes fullSig
                     return $ Right sigOnly

-- Verifies a message signature
verify :: ByteString -> ByteString -> ByteString -> IO (Either String Bool)
verify message signature publicKey = do
  publicKeyBytes <- cryptoSignPublicKeyBytes
  sigBytes <- cryptoSignBytes
  if BS.length publicKey /= publicKeyBytes
    then return $ Left "Invalid public key length"
    else useAsCStringLen message $ \(_, msgLen) ->
           useAsCStringLen (BS.append signature message) $ \(sigPtr, sigLen) ->
             useAsCStringLen publicKey $ \(pkPtr, _) -> do
               m <- mallocBytes (msgLen + sigBytes)
               mLen <- mallocBytes (sizeOf (undefined :: CSize))
               result <-
                 c_crypto_sign_open
                   (castPtr m)
                   mLen
                   (castPtr sigPtr)
                   (fromIntegral sigLen)
                   (castPtr pkPtr)
               return $ Right (result == 0)

-- Generates a keypair from a seed
generateKeypair :: ByteString -> IO (Either String (ByteString, ByteString))
generateKeypair seed = do
  seedBytes <- cryptoSignSeedBytes
  publicKeyBytes <- cryptoSignPublicKeyBytes
  secretKeyBytes <- cryptoSignSecretKeyBytes
  if BS.length seed /= seedBytes
    then return $ Left "Invalid seed length"
    else useAsCStringLen seed $ \(seedPtr, _) -> do
           publicKey <- mallocBytes publicKeyBytes
           secretKey <- mallocBytes secretKeyBytes
           c_crypto_sign_seed_keypair
             (castPtr publicKey)
             (castPtr secretKey)
             (castPtr seedPtr)
           pub <- packCStringLen (publicKey, publicKeyBytes)
           sec <- packCStringLen (secretKey, secretKeyBytes)
           return $ Right (pub, sec)
