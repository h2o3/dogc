module Secure (
decrypt, encrypt, initCipher
) where

import           Crypto.Cipher.AES
import           Crypto.Hash.MD5   (hash)
import qualified Data.ByteString   as BS
import           Data.Monoid       ((<>))


evpBytesToKey :: BS.ByteString -> Int -> Int -> (BS.ByteString, BS.ByteString)
evpBytesToKey password keyLen ivLen =
    let ms' = BS.concat $ ms 0 []
        key = BS.take keyLen ms'
        iv  = BS.take ivLen $ BS.drop keyLen ms'
     in (key, iv)
  where
    ms :: Int -> [BS.ByteString] -> [BS.ByteString]
    ms 0 _ = ms 1 [hash password]
    ms i m
        | BS.length (BS.concat m) < keyLen + ivLen =
            ms (i+1) (m ++ [hash (last m <> password)])
        | otherwise = m


pkcsPadding :: BS.ByteString -> Int -> BS.ByteString
pkcsPadding block size =
    let len = BS.length block
        mlen = len `mod` size
        pad = size - mlen
    in
        BS.concat [block, BS.replicate pad $ fromIntegral pad]


pkcsRemovePadding :: BS.ByteString -> BS.ByteString
pkcsRemovePadding block =
    let len = BS.length block
        pad = BS.last block
    in
        BS.take (len - fromIntegral pad) block


initCipher :: BS.ByteString -> (AES, BS.ByteString)
initCipher password = let (pwd, iv) = evpBytesToKey password 32 16 in (initAES pwd, iv)


encrypt :: AES -> BS.ByteString -> BS.ByteString -> BS.ByteString
encrypt cipher iv chunk = encryptCBC cipher iv $ pkcsPadding chunk 16


decrypt :: AES -> BS.ByteString -> BS.ByteString -> BS.ByteString
decrypt cipher iv chunk = pkcsRemovePadding $ decryptCBC cipher iv chunk
