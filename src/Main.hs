import           Control.Concurrent
import           Control.Concurrent.STM
import           Control.Exception
import           Control.Monad
import           Crypto.Cipher.AES
import           Crypto.Hash.MD5           (hash)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Char8     as BC
import           Data.Monoid               ((<>))
import           Data.Serialize
import           Data.Serialize.Get
import           Data.Serialize.Put
import           Network.Socket
import qualified Network.Socket.ByteString as NB
import           System.Environment
import           System.IO


data ProxyTransportProp = HTTP SockAddr String
                        | TCP SockAddr
                        deriving (Show)


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


talk :: Socket -> ProxyTransportProp -> BS.ByteString -> BS.ByteString -> IO ()
talk client transport key password = do
    proxy <- socket AF_INET Stream defaultProtocol

    -- connect to the proxy
    connectToProxy proxy transport

    exitSignal <- newTChanIO

    let (pwd, iv) = evpBytesToKey password 32 16
        cipher = initAES pwd
        final = threadFinalHandler exitSignal
        handleProxy = recvOnProxy transport proxy client cipher iv
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
        recvOnHandle client proxy cipher iv = loop where
            loop = do
                chunk <- NB.recv client 4096
                unless (BS.null chunk) $ do
                    let encrypted = encryptCBC cipher iv $ pkcsPadding chunk 16
                        len = BS.length encrypted
                        encodedLen = runPut $ putWord32be $ fromIntegral len
                        in NB.sendMany proxy [encodedLen, encrypted]
                    loop

        recvOnProxy transport proxy handle cipher iv = do
            buffer <- NB.recv proxy 65536
            loop chunkParser $ runGetPartial chunkParser buffer
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

        connectToProxy proxy transport = do
            case transport of
                HTTP sockAddr host -> do
                    connect proxy sockAddr
                    -- send http request
                    NB.sendMany proxy [
                        BC.pack "GET / HTTP/1.1\r\n",
                        BC.pack $ "Host: " ++ host ++ "\r\n",
                        BC.pack "Connection: Upgrade\r\n",
                        BC.pack "Upgrade: DOGS\r\n",
                        BC.pack "\r\n"]
                    -- recv http response headers
                    recvHeader proxy BS.empty
                    where
                        recvHeader proxy chunk = do
                            buffer <- NB.recv proxy 65536
                            unless (BS.null buffer) $
                                let newChunk = BS.concat [chunk, buffer]
                                    in unless (BS.isSuffixOf (BC.pack "\n\n") newChunk
                                        || BS.isSuffixOf (BC.pack "\r\n\r\n") newChunk) $
                                        recvHeader proxy newChunk
                TCP sockAddr -> connect proxy sockAddr

            NB.sendAll proxy $ runPut $ putWord8 $ fromIntegral $ BS.length key
            NB.sendAll proxy key

        chunkParser = do
            len <- getWord32be
            getByteString $ fromIntegral len

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
    protocol:host:port:key:password:_ <- getArgs

    transportProp <- case protocol of
        "tcp" -> do
            AddrInfo _ _ _ _ addr _ : _ <- getAddrInfo Nothing (Just host) (Just port)
            return $ TCP addr
        "http" -> do
            AddrInfo _ _ _ _ addr _ : _ <- getAddrInfo Nothing (Just host) (Just port)
            return $ HTTP addr host

    print transportProp

    socket <- socket AF_INET Stream defaultProtocol
    setSocketOption socket ReuseAddr 1

    bind socket (SockAddrInet 9001 iNADDR_ANY)
    listen socket 1024

    forever $ do
        (rSocket, addr) <- accept socket

        putStrLn $ "Hello " ++ show addr

        let proxyKey = BC.pack key
            proxyPwd = BC.pack password
            action = talk rSocket transportProp proxyKey proxyPwd
            final e = do
                finalMessage <- case e of
                    Left error -> return $ "Bye " ++ show addr ++ " with error: " ++ show error
                    otherwise -> return $ "Goodbye " ++ show addr
                putStrLn finalMessage
                close rSocket
            in forkFinally action final
