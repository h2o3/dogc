import Network.Socket
import qualified Network.Socket.ByteString as NB
import Data.Monoid ((<>))
import System.IO
import System.Environment
import Control.Monad
import Control.Exception
import Control.Concurrent
import Control.Concurrent.STM
import Data.Serialize
import Data.Serialize.Put
import Data.Serialize.Get
import Crypto.Cipher.AES
import Crypto.Hash.MD5 (hash)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC


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


pkcsRemovePadding :: BS.ByteString -> Int -> BS.ByteString
pkcsRemovePadding block size =
    let len = BS.length block
        pad = BS.last block
    in
        BS.take (len - fromIntegral pad) block


talk :: Socket -> SockAddr -> BS.ByteString -> BS.ByteString -> IO ()
talk client proxyAddr key password = do
    proxy <- socket AF_INET Stream defaultProtocol

    connect proxy proxyAddr

    -- handshake
    NB.sendAll proxy $ runPut $ putWord8 $ fromIntegral $ BS.length key
    NB.sendAll proxy key

    exitSignal <- newTChanIO

    let (pwd, iv) = evpBytesToKey password 32 16
        cipher = initAES pwd
        final = threadFinalHandler exitSignal
        handleProxy = recvOnProxy proxy client cipher iv
        handleClient = recvOnHandle client proxy cipher iv
        in do
            -- fork receive thread - handle
            handleReceiveThread <- forkFinally handleClient final
            -- fork receive thread - proxy
            proxyReceiveThread <- forkFinally handleProxy final

            -- cleanup
            join $ atomically $ do
                _ <- readTChan exitSignal
                return $ cleanup [proxy] [handleReceiveThread, proxyReceiveThread]
    where
        recvOnHandle client proxy cipher iv = loop
            where
                loop = do
                    chunk <- NB.recv client 4096
                    unless (BS.null chunk) $ do
                        let encrypted = encryptCBC cipher iv $ pkcsPadding chunk 16
                            len = BS.length encrypted
                            encodedLen = runPut $ putWord32be $ fromIntegral len
                            in NB.sendMany proxy [encodedLen, encrypted]
                        loop

        recvOnProxy proxy handle cipher iv =
            let parser = do
                    len <- getWord32be
                    getByteString $ fromIntegral len
                in do
                    buffer <- NB.recv proxy 65536
                    loop parser $ runGetPartial parser buffer
                    where
                        loop parser (Done chunk restBuffer) = do
                            -- decrypt and forward to client
                            let clearChunk = pkcsRemovePadding (decryptCBC cipher iv chunk) 16
                                in NB.sendAll handle clearChunk

                            loop parser $ runGetPartial parser restBuffer
                        loop parser (Partial continue) = do
                            buffer <- NB.recv proxy 65536
                            unless (BS.null buffer) $
                                loop parser $ continue buffer
                        loop _ (Fail err _) = error err

        threadFinalHandler exitSignal e = do
            case e of
                Left err -> print err
                otherwise -> return ()
            atomically $ writeTChan exitSignal True

        cleanup sockets threads = do
            putStrLn "cleanup"
            mapM_ killThread threads
            mapM_ close sockets


main :: IO ()
main = do
    (ip:port:key:password:_) <- getArgs

    proxyIp <- inet_addr ip

    socket <- socket AF_INET Stream defaultProtocol
    setSocketOption socket ReuseAddr 1

    bind socket (SockAddrInet 9002 iNADDR_ANY)
    listen socket 1024

    forever $ do
        (rSocket, addr) <- accept socket

        putStrLn $ "Hello " ++ show addr

        let proxyAddr = SockAddrInet (fromIntegral (read port)) proxyIp
            proxyKey = BC.pack key
            proxyPwd = BC.pack password
            action = talk rSocket proxyAddr proxyKey proxyPwd
            final e = do
                finalMessage <- case e of
                    Left error -> return $ "Bye " ++ show addr ++ " with error: " ++ show error
                    otherwise -> return $ "Goodbye " ++ show addr
                putStrLn finalMessage
                close rSocket
            in forkFinally action final
