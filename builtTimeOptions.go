package hq

const (

	// rename the app here, to use  different [privat|corp] custom versions via different binary executables in parallel
	_extSignature  = ".hqs"
	_extExecutable = ".hqx"
	_extSignify    = ".sig"

	// staticly enforce [no] color mode without env variable FORCE_COLOR=true
	_forceNoColor = false

	// staticly force to clean all pre-existing  .hqMAP.* entries before create a new one
	_forceMapClean = true

	// [zstd 1-22] compression level for .hqx container [shell script compression]
	// defaults for best results b/c maps == highEntropy
	_compressedScriptLevel = 22
	_compressedMapLevel    = 1
	_compressedFileExt     = ".zst"

	// minimum acceptable [text] password
	_minimumPasswordLen = 6

	// globally disable report timing of every operation
	_reportTime = true

	// name of the symolic link / id
	_me = "me"

	// custom env variable names
	_envHQOWNER    = "HQ_OWNER"
	_envHQSigOnly  = "HQ_SIG_ONLY"
	_envHQMapOnly  = "HQ_MAP_ONLY"
	_envHQMapClean = "HQ_MAP_CLEAN"
	_envHQSignify  = "HQ_ADD_SIGNIFY"

	// HQs shebang header
	_sheBang = "#!/usr/bin/hq\n"
	// ###########################
	// # SECURITY POLICY SECTION #
	// ###########################

	// allow to provide passwords via env variables [batch|test|bench]
	// _allow_password_via_env = false
	_allowUnlockViaEnv = true

	// # executeable interpreter
	// disabled -> to disable execution at all
	// builtin -> use internal, build-in interpreter [XXX TODO sh upstream fix needed]
	// <path>   -> for external interpreter
	_sh     = "/bin/sh"
	_zsh    = "/usr/bin/zsh"
	_fish   = "disabled"
	_bash   = "disabled"
	_lua    = "/usr/bin/lua"
	_perl   = "/usr/bin/perl"
	_python = "/usr/bin/python"
	_hhvm   = "disabled"
	_js     = "disabled"
	_java   = "disabled"
	_pwsh   = "disabled"

	// ######################################################################################################
	// # ANY MODIFICATION BELOW WILL MAKE YOUR HQ BINARY KEY INCOMPATIBLE WITH THE PUBLIC RELEASED VERSION  #
	// ######################################################################################################
	// ... use modified versions only wihtin a closed environment and rename the binary to: hq-<corporate-name> | hq-private

	// # kmac
	// [tldr: additional salt]
	// -> set an individual key to protect against pre-computed rainbow tables
	// -> any random noise will do
	// -> your hq keys, signatures [.hqs,.hqx]  will NOT contain|leak your kmac
	// -> your individual hq binary WILL [expose|leak] your kmac
	_hashKMAC = ("THIS IS THE DEFAULT HQ KMAC MESSAGE TEXT & KEY")

	// # memlimit
	// [tldr: memory size|latency|bw hardness]
	// -> memory size|latency|bw is power|chipsize expensive, even on custom silicon ASIC|GPU|FPGA
	// -> its an generic unitless scale factor, results may vary
	// -> allow an individual high memlimit to cause pain
	// -> restrict an individual low memlimit for [embedded|memory constrained] envs
	_memlimit int = 128 * 1024 // 128 MB

	// # layer
	// [tldr: [memory|bandwidth|latency|logic] hardness]
	// - add additional layer to you hash-cube to [expot] add complexity
	_layer int = 1

	// # threads
	// [tldr: hardness against simple single-core [GPU/ASIC/FPGA] logic]
	_parallel int = 8
)
