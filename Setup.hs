import           Distribution.Simple                   (Args,
                                                        defaultMainWithHooks,
                                                        postClean, preConf,
                                                        simpleUserHooks)
import           Distribution.Simple.Setup             (CleanFlags, ConfigFlags)
import           Distribution.Types.HookedBuildInfo    (HookedBuildInfo,
                                                        emptyHookedBuildInfo)
import           Distribution.Types.PackageDescription (PackageDescription)
import           System.Exit                           (ExitCode (..),
                                                        exitFailure)
import           System.Process                        (system)

-- | Entry point of the custom Setup script.
main :: IO ()
main =
  defaultMainWithHooks
    simpleUserHooks {preConf = preConfHook, postClean = postCleanHook}

-- | Hook to be executed before the configure step.
--   Builds the SPHINCS+ C library with the specified PARAMS.
--   Exits with an error if the build fails.
preConfHook :: Args -> ConfigFlags -> IO HookedBuildInfo
preConfHook _ _ = do
  putStrLn "Building SPHINCS+ C library with PARAMS=sphincs-haraka-128f..."
  -- Run the make command to build the library
  result <-
    system "make -C src/sphincsplus/ref CFLAGS=\"-DPARAMS=sphincs-haraka-128f\""
  case result of
    ExitSuccess -> do
      putStrLn "SPHINCS+ C library built successfully."
      return emptyHookedBuildInfo
    ExitFailure _ -> do
      putStrLn "Failed to build SPHINCS+ C library."
      exitFailure

-- | Hook to be executed after the clean step.
--   Cleans the SPHINCS+ C library using the `make clean` command.
postCleanHook :: Args -> CleanFlags -> PackageDescription -> () -> IO ()
postCleanHook _ _ _ _ = do
  putStrLn "Cleaning SPHINCS+ C library..."
  _ <- system "make -C src/sphincsplus/ref clean"
  putStrLn "SPHINCS+ C library cleaned successfully."
