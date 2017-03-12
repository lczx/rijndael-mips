::#!
:: ASM RIJNDAEL ENCRYPTION SCRIPT (aes-encrypt)
@echo off
set s=%~n0
call scala %s%.cmd %*
:: vv Otherwise it doesn't work...
exit /b %errorlevel%
::!#

/* MarsWrapper.scala */
// Can't resist the temptation to use EPFL's Scala!

import java.io.{BufferedReader, InputStreamReader}

// Define java arguments
val javaArgs = "java -jar lib/Mars4_4.jar" split " "

// Define simulation arguments
def simArgs = Array(
  "sm", // Start execution at global main
  "nc", // Do not display copyright notice
  "p",  // Project mode, assemble all files
  _: String, // Entry point inside here!
  "pa"  // Program arguments following
)

val pb = new ProcessBuilder((javaArgs ++ simArgs("asm/main.asm") ++ args):_*)

// Start Mars with concatenated program and simulation arguments
try {
  val p = pb.start
  // We could have done writing to stderr by outputting to file descriptor 2 from MARS but we do it here...
  val input = new BufferedReader(new InputStreamReader(p.getInputStream))
  Stream continually input.readLine() takeWhile (_ != null) foreach Console.err.println // Here we print to stderr.
  input.close()
  p.waitFor()
  
  println(s"\n>> Process terminated with error code ${p.exitValue}")
  System.exit(p.exitValue)
}
catch { case e: Exception => e.printStackTrace() }

// vim: filetype=scala
