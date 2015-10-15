module Concurrent (
  forkAndWaitAny, forkManyWithFinally
  ) where

import           Control.Concurrent
import           Control.Concurrent.STM
import           Control.Exception
import           Control.Monad


forkAndWaitAny :: [IO ()] -> (Either SomeException () -> IO()) -> IO () -> IO ()
forkAndWaitAny tasks finalHook cleanupHook = do
  chan <- newTChanIO
  threads <- let final = finalHandler chan finalHook
             in forkManyWithFinally final tasks []
  join $ atomically $ do
    _ <- readTChan chan
    return $ cleanup cleanupHook threads
  where
    finalHandler chan hook result = do
      _ <- hook result
      atomically $ writeTChan chan True
    cleanup hook threads = do
      mapM_ killThread threads
      hook


forkManyWithFinally :: (Either SomeException () -> IO()) -> [IO()] -> [ThreadId] -> IO [ThreadId]
forkManyWithFinally _ [] threadIds = return threadIds
forkManyWithFinally final (task:rest) threadIds = do
  threadId <- forkFinally task final
  forkManyWithFinally final rest $ threadId:threadIds
