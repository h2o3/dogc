module Client (main) where

import           Concurrent                (forkAndWaitAny)
import           Control.Concurrent
import           Control.Monad
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Char8     as BC
import           Data.Serialize.Get
import           Data.Serialize.Put
import           Network.Socket
import qualified Network.Socket.ByteString as NB
import           Secure                    (decrypt, encrypt, initCipher)
import           System.Environment


data ProxyTransportProp = HTTP SockAddr String
                        | TCP SockAddr
                        deriving (Show)


talk :: Socket -> ProxyTransportProp -> BS.ByteString -> IO ()
talk client transport password = do
    proxy <- socket AF_INET Stream defaultProtocol

    -- connect to the proxy
    connectToProxy proxy

    let (cipher, iv) = initCipher password
        handleProxy = recvOnProxy proxy cipher iv
        handleClient = recvOnHandle proxy cipher iv
        in forkAndWaitAny [handleProxy, handleClient] threadFinalHandler $ cleanup proxy
    where
        recvOnHandle proxy cipher iv = loop where
            loop = do
                chunk <- NB.recv client 65000
                unless (BS.null chunk) $ do
                    let encrypted = encrypt cipher iv chunk
                        len = BS.length encrypted
                        encodedLen = runPut $ putWord16be $ fromIntegral len
                        in NB.sendMany proxy [encodedLen, encrypted]
                    loop

        recvOnProxy proxy cipher iv = do
            buffer <- NB.recv proxy 65536
            loop chunkParser $ runGetPartial chunkParser buffer
            where
                loop parser (Done chunk restBuffer) = do
                    -- decrypt and forward to client
                    let clearChunk = decrypt cipher iv chunk
                        in NB.sendAll client clearChunk

                    loop parser $ runGetPartial parser restBuffer
                loop parser (Partial continue) = do
                    buffer <- NB.recv proxy 65536
                    unless (BS.null buffer) $
                        loop parser $ continue buffer
                loop _ (Fail err _) = error err

        connectToProxy proxy =
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
                    recvHeader BS.empty
                    where
                        recvHeader chunk = do
                            buffer <- NB.recv proxy 65536
                            unless (BS.null buffer) $
                                let newChunk = BS.concat [chunk, buffer]
                                    in unless (BS.isSuffixOf (BC.pack "\n\n") newChunk
                                        || BS.isSuffixOf (BC.pack "\r\n\r\n") newChunk) $
                                        recvHeader newChunk
                TCP sockAddr -> connect proxy sockAddr

        chunkParser = do
            len <- getWord16be
            getByteString $ fromIntegral len

        threadFinalHandler e =
            case e of
                Left err -> print err
                _ -> return ()

        cleanup so = do
            putStrLn "cleanup"
            close so


main :: IO ()
main = do
    protocol:host:port:password:_ <- getArgs

    transportProp <- case protocol of
        "tcp" -> do
            AddrInfo _ _ _ _ addr _ : _ <- getAddrInfo Nothing (Just host) (Just port)
            return $ TCP addr
        "http" -> do
            AddrInfo _ _ _ _ addr _ : _ <- getAddrInfo Nothing (Just host) (Just port)
            return $ HTTP addr host
        _ -> error "only support tcp/http"

    print transportProp

    so <- socket AF_INET Stream defaultProtocol
    setSocketOption so ReuseAddr 1

    bind so (SockAddrInet 9001 iNADDR_ANY)
    listen so 1024

    forever $ do
        (client, addr) <- accept so

        putStrLn $ "Hello " ++ show addr

        let proxyPwd = BC.pack password
            action = talk client transportProp proxyPwd
            final e = do
                finalMessage <- case e of
                    Left err -> return $ "Bye " ++ show addr ++ " with error: " ++ show err
                    _ -> return $ "Goodbye " ++ show addr
                putStrLn finalMessage
                close client
            in forkFinally action final
