module Server (main) where

import           Concurrent                (forkAndWaitAny)
import           Control.Concurrent
import           Control.Monad
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Char8     as BC
import           Data.Serialize.Get
import           Data.Serialize.Put
import           Network.Socket
import qualified Network.Socket.ByteString as NB
import           Secure
import           System.Environment


data TransportProp = HTTP
                   | TCP
                   deriving (Show)


talk :: Socket -> TransportProp -> BS.ByteString -> SockAddr -> IO ()
talk client transProp pwd addr = do
  handShake

  proxy <- socket AF_INET Stream defaultProtocol
  connect proxy addr

  let (cipher, iv) = initCipher pwd
      proxyAction = proxyProcess proxy cipher iv
      clientAction = clientProcess proxy cipher iv
      in forkAndWaitAny [proxyAction, clientAction] final $ close proxy
  where
    handShake =
      case transProp of
        HTTP -> do
          recvHeader BS.empty
          NB.sendMany client [
            BC.pack "200 OK HTTP/1.1\r\n",
            BC.pack "Connection: Upgrade\r\n",
            BC.pack "Upgrade: DOGS\r\n",
            BC.pack "\r\n"]
        TCP -> return ()
      where
        recvHeader chunk = do
          buffer <- NB.recv client 65536
          unless (BS.null buffer) $
            let newChunk = BS.concat [chunk, buffer]
            in unless (BS.isSuffixOf (BC.pack "\n\n") newChunk
                       || BS.isSuffixOf (BC.pack "\r\n\r\n") newChunk) $
               recvHeader newChunk

    proxyProcess proxy cipher iv = loop where
      loop = do
        buffer <- NB.recv proxy 65000
        unless (BS.null buffer) $ do
          let encrypted = encrypt cipher iv buffer
              len = BS.length encrypted
              encodedLen = runPut $ putWord16be $ fromIntegral len
              in NB.sendMany client [encodedLen, encrypted]
          loop

    clientProcess proxy cipher iv =
      loop $ runGetPartial chunkParser BS.empty
      where
        loop (Done result remain) = do
          let clear = decrypt cipher iv result
              in NB.sendAll proxy clear
          loop $ runGetPartial chunkParser remain
        loop (Partial continuation) = do
          buffer <- NB.recv client 65536
          if not $ BS.null buffer
            then loop $ continuation buffer
            else error "EOF"
        loop (Fail err _) = error err

    chunkParser = do
      len <- getWord16be
      getByteString $ fromIntegral len

    final (Left err) = print err
    final _ = return ()


main :: IO ()
main = do
  protocol:host:port:password:_ <- getArgs

  AddrInfo _ _ _ _ addr _ : _ <- getAddrInfo Nothing (Just host) (Just port)

  transportProp <- case protocol of
    "tcp" -> return TCP
    "http" -> return HTTP
    _ -> error "neither TCP or HTTP"

  print transportProp
  print addr

  serverSocket <- socket AF_INET Stream defaultProtocol
  setSocketOption serverSocket ReuseAddr 1
  bind serverSocket (SockAddrInet 9000 iNADDR_ANY)
  listen serverSocket 1024

  forever $ do
    (client, remoteAddr) <- accept serverSocket

    putStrLn $ "Hello " ++ show remoteAddr

    let proxyPwd = BC.pack password
        action = talk client transportProp proxyPwd addr
        final e = do
          msg <- case e of
            Left err -> return $ "Bye " ++ show remoteAddr ++ " with error: " ++ show err
            _ -> return $ "Bye " ++ show remoteAddr
          putStrLn msg
          close client
        in forkFinally action final
