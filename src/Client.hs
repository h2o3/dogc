module Client (main) where

import           Codec.Compression.GZip    (compress, decompress)
import           Concurrent                (forkAndWaitAny)
import           Control.Concurrent
import           Control.Monad
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Char8     as BC
import qualified Data.ByteString.Lazy      as L
import           Data.Serialize
import           Data.Serialize.Get
import           Data.Serialize.Put
import           Network.Socket
import qualified Network.Socket.ByteString as NB
import           Secure                    (decrypt, encrypt, initCipher)
import           System.Environment


data ProxyTransportProp = HTTP SockAddr String
                        | TCP SockAddr
                        deriving (Show)


talk :: Socket -> ProxyTransportProp -> BS.ByteString -> BS.ByteString -> IO ()
talk client transport key password = do
    proxy <- socket AF_INET Stream defaultProtocol

    -- connect to the proxy
    connectToProxy proxy transport

    let (cipher, iv) = initCipher password
        handleProxy = recvOnProxy transport proxy client cipher iv
        handleClient = recvOnHandle client proxy cipher iv
        in forkAndWaitAny [handleProxy, handleClient] threadFinalHandler $ cleanup proxy
    where
        recvOnHandle client proxy cipher iv = loop where
            loop = do
                chunk <- NB.recv client 65000
                unless (BS.null chunk) $ do
                    let encrypted = L.toStrict $ compress $ L.fromStrict $ encrypt cipher iv chunk
                        len = BS.length encrypted
                        encodedLen = runPut $ putWord16be $ fromIntegral len
                        in NB.sendMany proxy [encodedLen, encrypted]
                    loop

        recvOnProxy transport proxy handle cipher iv = do
            buffer <- NB.recv proxy 65536
            loop chunkParser $ runGetPartial chunkParser buffer
            where
                loop parser (Done chunk restBuffer) = do
                    -- decrypt and forward to client
                    let clearChunk = decrypt cipher iv $ L.toStrict $ decompress $ L.fromStrict chunk
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
            len <- getWord16be
            getByteString $ fromIntegral len

        threadFinalHandler e =
            case e of
                Left err -> print err
                otherwise -> return ()

        cleanup socket = do
            putStrLn "cleanup"
            close socket


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
