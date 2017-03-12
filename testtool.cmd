::#!
@echo off
set s=%~n0
call scala -cp "lib/jansi-1.11.jar;lib/Mars4_4.jar" %s%.cmd %*
exit /b
::!#

import scala.language.implicitConversions
import scala.collection.mutable.ListBuffer
import scala.io.Source
import Console._ // Escape sequences from scala.Console

import java.io.{BufferedReader, File, InputStreamReader, OutputStream, PrintStream}
import java.security.{MessageDigest, Permission}
import java.util.Arrays

import org.fusesource.jansi.AnsiConsole.out.{print => aprint, println => aprintln} // Ansi Console output



showTitle()
if (args contains "help") printUsage()

val dbgMode = args contains "debug"
val hltMode = args contains "halt"
val prcMode = args contains "nohook"

if (dbgMode) println(" -- DEBUG --")

val tStats = ListBuffer[(Int, Int)]()

val runTime = timeProfile {
  tStats += runTestCollection(1, "Unaligned source, part", "test/h.txt")
  tStats += runTestCollection(2, "Aligned source, 1 block", "test/1b.txt")
  tStats += runTestCollection(3, "Unaligned source, 11 blocks + part", "test/11b+h.txt")
  tStats += runTestCollection(4, "Aligned source, 3 blocks", "test/3b.txt")
}

val tStatsRes = tStats.fold((0,0)) { (a, b) => (a._1 + b._1, a._2 + b._2) }
aprint(s"\n$BOLD$GREEN${tStatsRes._1} tests passed$WHITE")
val tStatsFailCount = tStatsRes._2 - tStatsRes._1
if (tStatsFailCount > 0) aprint(s", $RED$tStatsFailCount failed$WHITE,")
aprintln(s" out of a total of ${tStatsRes._2}.$RESET")

val elapsedSec = runTime / 1000000000d
val elapsedMin = scala.math.floor(elapsedSec/60)
println(f"Completed in $elapsedMin%.0f minutes and ${elapsedSec - elapsedMin*60}%.1f seconds ($elapsedSec%.1f s).")




/** Time profiles the given block, by evaluating it by-name */
def timeProfile(block: => Unit): Long = {
  val t0 = System.nanoTime
  block // call-by-name
  val t1 = System.nanoTime

  (t1 - t0)
}

/** Runs a test collection on the given described file. Returns a touple of succeeded / total amount of tests. */
def runTestCollection(n: Int, desc: String, srcFile: String) = {
  aprintln(s"\n$BOLD$CYAN" + s"TEST #$n$WHITE - $desc$RESET")
  var collSuccessCount = 0
  for (e <- AESKeySize.values; p <- Set(false, true); o <- AESBlockMethod.values)
    collSuccessCount += evalTest(srcFile, e, o, p, dbgMode)

  (collSuccessCount, 12) // 16 is total amt. of tests
}

/** Evaluates the given test, encrypts the provided file both with OpenSSL and Ares, then compares the results */
def evalTest(inFile: String, keySize: AESKeySize.Value, opMode: AESBlockMethod.Value, padding: Boolean, debug: Boolean = false) = {

  val partialArgFunction = genArgs(keySize, opMode, padding)

  // Here we write what we are testing on screen
  print(s"  AES-${getBits(keySize)} ${getMode(opMode).toUpperCase}, " + (if (padding) "w/" else "no") + " pad")

  // ---vv--- Command execution following ---vv---
  val outFiles = List("ossl", "ares") map (s => "~out_" + s + "_" + inFile.split('/').last) // Output file names here!

  val ret1 = runKernel(partialArgFunction("openssl", inFile, outFiles(0)), debug)
  val ret2 = runKernel(partialArgFunction("ares.cmd", inFile, outFiles(1)), debug)

  // OpenSSL decided to output an empty file even in case of error...
  // So we check for its its exit code to be EXIT_SUCCESS before computing its md5, simple.
  val md1 = if (ret1 == 0) md5file(outFiles(0)) else None
  val md2 = if (ret2 == 0) md5file(outFiles(1)) else None
  if (debug) {
    println(s"OSSL($ret1): " + (if (md1.isEmpty) "--NONE--" else hex2str(md1.get)))
    println(s"ARES($ret2): " + (if (md2.isEmpty) "--NONE--" else hex2str(md2.get)))
  }

  def handleResultSuccess(msg: String) = { aprintln(s"\t$BOLD$GREEN OK$RESET$GREEN  $msg$RESET"); true }
  def handleResultFailure(msg: String) = { aprintln(s"\t$BOLD$RED ERROR$RESET$RED  $msg$RESET"); false }

  val result = (md1, md2) match {
    case (Some(hash1), Some(hash2)) if (Arrays.equals(hash1, hash2)) =>
      handleResultSuccess(s"MD5 MATCH$RESET\t    ${hex2str(hash1)}") // Output equality
    case (Some(hash1), Some(hash2)) =>
      handleResultFailure("MD5 MISMATCH") // Output mismatch
    case (None, None) =>
      handleResultSuccess("NOT COMPUTED") // No output from both algos, impossible on reference impl, OK
    case _ =>
      handleResultFailure("UNEXPECTED BEHAVIOR") // Remaining cases (es. out from only an algo) are considered unexpected
  }

  if (!result && hltMode) System.exit(1)

  if (debug) println() // Pure --debug-- aesthetics
  outFiles foreach (new File(_).delete()) // Delete outputs

  if (result) 1 else 0
}



// Executes the passed commandline and returns its exit code, if debug is enabled it will print out stderr information
def runKernel(args: List[String], debug: Boolean = false) = {
  if (debug) println("\n>>> " + args.mkString(" ")) // This before all so we display it anyways

  if (!prcMode && args.head == "ares.cmd") { // ARES arguments can be directly passed to the MARS simulator
    // Forbid exit calls from now on, otherwise MARS will close our script while exiting.
    SecurityUtil.forbidExitCalls()

    // MARS arguments, see "ares.cmd" if you wanna know more
    def simArgs = Array("sm", "nc", "p", _: String, "pa")

    val exitValue = try { disableSystemOut(debug) {
      Mars.main(simArgs("asm/main.asm") ++ args.tail)
    } }
    catch { case ExitException(exitCode) => exitCode }

    SecurityUtil.allowExitCalls()
    exitValue // Return dah EXITVALLLLUUUEEEEE
  }
  else {
    val proc = new ProcessBuilder(args: _*).start
    if (debug) { // If we are debugging, catching the process' output and printing it may be useful.
      val stderr = new BufferedReader(new InputStreamReader(proc.getErrorStream)) // <<= NOTE THAT WE USE STDERR!!
      Stream continually stderr.readLine() takeWhile(_ != null) foreach println
      stderr.close()
    }
    proc.waitFor() // Wait 'till end
    proc.exitValue // Return dah ezit c0de
  }
}


/** Disables the output stream at Java level; if 'ovd' is true, the stream will not be redirected */
def disableSystemOut[T](ovd: Boolean = false)(thunk: => T): T = {
  // An output stream that prints nothing, useful if we are not in 'debug'
  val sinkStream = new PrintStream(new OutputStream() { override def write(byte: Int) = () })
  if (!ovd) System.setOut(sinkStream)
  val ret = thunk
  if (!ovd) System.setOut(System.out)
  ret
}


def genArgs(keysize: AESKeySize.Value, opmode: AESBlockMethod.Value, padding: Boolean): (String, String, String) => List[String] = {
  val retArgs = ListBuffer[String]()

  retArgs += s"-aes-${getBits(keysize)}-${getMode(opmode)}" // Add encr. algorithm argument

  if (opmode == AESBlockMethod.CBC) // Set IV if we are in CBC
    retArgs += ("-iv", "00020406080a0c0e0020406080a0c0e0")

  retArgs += ("-K", keysize match { // Set key
    case AESKeySize.AES128 => "00112233445566778899aabbccddeeff"
    case AESKeySize.AES192 => "00112233445566778899aabbccddeeff0011223344556677"
    case AESKeySize.AES256 => "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
  })

  if (!padding) retArgs += "-nopad" // Add padding argument

  (cmd: String, inFile: String, outFile: String) =>
    (cmd +: "enc" +: retArgs :+ "-in" :+ inFile :+ "-out" :+ outFile).toList
}

def getBits = (_: AESKeySize.Value) match {
  case AESKeySize.AES128 => 128
  case AESKeySize.AES192 => 192
  case AESKeySize.AES256 => 256
}

def getMode = (_: AESBlockMethod.Value) match {
  case AESBlockMethod.ECB => "ecb"
  case AESBlockMethod.CBC => "cbc"
}



def showTitle() {
  var sslVerProc = new ProcessBuilder("openssl", "version").start
  val sslVerOut = new BufferedReader(new InputStreamReader(sslVerProc.getInputStream))
  val sslVerData = sslVerOut.readLine() split " "
  sslVerOut.close();
  sslVerProc.waitFor()
  val sslVer = s"OpenSSL / SSLeay ${sslVerData(1)} (${sslVerData drop 3 mkString " "})"

  val title = BOLD + "ARES functionality test tool, proudly powered by " +
    (((1 to 6) ++ (1 to 6) zip "IMMAGINATION") map (x => "\u001B[3" + x._1 + "m" + x._2)).mkString + RESET
  val notice = f"$sslVer%-42s MARS 4.4 runtime (Aug 2013)"

  println("   " + '\u00da' + '\u00c4'.toString * 70 + '\u00bf')
  aprintln(s"   \u00b3    $title     \u00b3")
  aprintln(s"   \u00b3$notice\u00b3")
  println("   " + '\u00c0' + '\u00c4'.toString * 70 + '\u00d9')
  println()
}

def printUsage() {
  println("""|Usage:\ttesttool [args]
             |
             |[args]
             |  help      Prints this scribble and exits.
             |  debug     Shows debug information and command lines executed.
             |  halt      Stops execution on failed results, without deleting output files.
             |  nohook    Disables Java hook, thus slowing down execution by ~1000%.""".stripMargin)

  System exit 0
}


/** Calulates the MD5 digest of the given file */
def md5file(file: String): Option[Array[Byte]] = {
  val md = MessageDigest.getInstance("MD5")
  md.reset()
  try {
    val src = Source.fromFile(file)(scala.io.Codec.ISO8859) // If not codec'd may give error
    val bytes = src.map(_.toByte).toArray
    src.close()
    md.update(bytes)
    Some(md.digest)
  }
  catch { case e: Exception => e.printStackTrace(); None}
}

def hex2str(bytes: Array[Byte]): String =
  bytes.map(0xFF & _).map { "%02x".format(_) }.foldLeft("") {_ + _}


/** Enumerations for AES operation modes (key size and block cipher mode */
object AESKeySize extends Enumeration { val AES128, AES192, AES256 = Value }
object AESBlockMethod extends Enumeration { val ECB, CBC = Value }

/** System.exit() trapping exception */
case class ExitException(code: Int) extends SecurityException

/** System.exit() trapping utility hook class */
object SecurityUtil {
  def forbidExitCalls() {
    val sm = new SecurityManager() {
      override def checkPermission(p: Permission) { /*println(p.getName)*/ }

      override def checkPermission(p: Permission, pCtx: AnyRef) { }

      override def checkExit(exitCode: Int) {
        super.checkExit(exitCode)
        throw new ExitException(exitCode)
      }
    }

    System.setSecurityManager(sm)
  }

  def allowExitCalls() {
    System.setSecurityManager(null)
  }
}

// vim: filetype=scala
