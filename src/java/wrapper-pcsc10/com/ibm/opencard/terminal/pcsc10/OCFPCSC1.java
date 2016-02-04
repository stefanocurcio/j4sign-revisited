/* Code derived from the original OpenCard Framework */
/*
 * Copyright © 1997 - 1999 IBM Corporation.
 * 
 * Redistribution and use in source (source code) and binary (object code)
 * forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 1. Redistributed source code must retain the above copyright notice, this
 * list of conditions and the disclaimer below.
 * 2. Redistributed object code must reproduce the above copyright notice,
 * this list of conditions and the disclaimer below in the documentation
 * and/or other materials provided with the distribution.
 * 3. The name of IBM may not be used to endorse or promote products derived
 * from this software or in any other form without specific prior written
 * permission from IBM.
 * 4. Redistribution of any modified code must be labeled "Code derived from
 * the original OpenCard Framework".
 * 
 * THIS SOFTWARE IS PROVIDED BY IBM "AS IS" FREE OF CHARGE. IBM SHALL NOT BE
 * LIABLE FOR INFRINGEMENTS OF THIRD PARTIES RIGHTS BASED ON THIS SOFTWARE.  ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IBM DOES NOT WARRANT THAT THE FUNCTIONS CONTAINED IN THIS
 * SOFTWARE WILL MEET THE USER'S REQUIREMENTS OR THAT THE OPERATION OF IT WILL
 * BE UNINTERRUPTED OR ERROR-FREE.  IN NO EVENT, UNLESS REQUIRED BY APPLICABLE
 * LAW, SHALL IBM BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.  ALSO, IBM IS UNDER NO OBLIGATION
 * TO MAINTAIN, CORRECT, UPDATE, CHANGE, MODIFY, OR OTHERWISE SUPPORT THIS
 * SOFTWARE.
 */

package com.ibm.opencard.terminal.pcsc10;
//ROB: Commented out to eliminate dependencies from opencard.core.util.Tracer
//import opencard.core.util.Tracer;

/** <tt>OCFPCSC1</tt> for PCSC card terminals.
  * Original class from OCF framework thats maps native methods.
  * Modified to eliminate dependencies from opencard.core.util.Tracer
  * 
  * @author  Roberto Resoli
  * @version $Id: OCFPCSC1.java,v 1.3 2011/01/13 07:34:02 resoli Exp $
  */

public class OCFPCSC1 {

//ROB: Commented out to eliminate dependencies from opencard.core.util.Tracer
//  private Tracer iTracer = new Tracer(this, OCFPCSC1.class);

  /** Constructor with initialization of the OCF tracing mechanism.
   *  @exception com.ibm.opencard.terminal.pcsc10.PcscException
   *		 thrown when error occured in PC/SC-Interface
   */
  public OCFPCSC1() throws PcscException {
      //ROB: Commented out to eliminate dependencies from:
      // opencard.core.util.Tracer
     //initTrace();
  }
  
  /* load the Wrapper-DLL */
  static public void loadLib() {
    try {

      //netscape.security.PrivilegeManager.enablePrivilege("UniversalLinkAccess");
      
      //ROB: Decommented (used instead of:
      //opencard.core.util.SystemAccess.getSystemAccess().loadLibrary()
      System.loadLibrary("OCFPCSC1");
      
      //ROB: commented to avoid dependencies from core ocf packages
      //opencard.core.util.SystemAccess.getSystemAccess().loadLibrary("OCFPCSC1");

    } catch (Exception e) {
      e.printStackTrace();
    }
  }
  /**************************************************************/
  /*								*/
  /* native Methods						*/
  /*								*/
  /**************************************************************/

  /* initialize the native tracing mechanism */
  public native void initTrace();

  /* returns a list of terminals found in the PCSC resource manager */
  public native synchronized String[] SCardListReaders(String groups)
				  throws PcscException;

  /* returns the context */
  public native synchronized int  SCardEstablishContext(int scope)
				  throws PcscException;

  public native synchronized void SCardReleaseContext(int context)
				  throws PcscException;

  /* returns the SCARDHANDLE */
  public native synchronized int  SCardConnect(int context, String reader,
				  int shareMode, int preferredProtocol, Integer activeProtocol)
				  throws PcscException;

  public native synchronized void SCardReconnect(int card, int shareMode,
				  int preferredProtocoll,  int initialization, Integer activeProtocol)
				  throws PcscException;

  public native synchronized void SCardDisconnect(int card, int disposition)
				  throws PcscException;

  public native synchronized void SCardGetStatusChange(int context, int timeout, PcscReaderState[] readerState)
				  throws PcscException;

  /* returns the AttributeBuffer */
  public native synchronized byte[] SCardGetAttrib(int card, int attrId)
				  throws PcscException;

  /* returns the count of received bytes in OutBuffer */
  public native synchronized byte[] SCardControl(int card, int controlCode, byte[] inBuffer)
				  throws PcscException;

  /* returns the receiveBuffer */
  /* the DLL has to manage the special behaviour of the T0/T1 protocol */
  public native synchronized byte[] SCardTransmit(int card, byte[] sendBuffer)
				  throws PcscException;

//ROB: msg callback method commented out to
//  eliminate dependencies from opencard.core.util.Tracer

/* is called by the native methods to trace via OCF trace mechanism */
/*
  protected void msg(int level, String methodName, String aLine) {
    iTracer.error("OCFPCSC1." + methodName, aLine);
  }
*/

}

// $Log: OCFPCSC1.java,v $
// Revision 1.3  2011/01/13 07:34:02  resoli
// Support CAdES and SHA-256 - Made Installer 64bit aware.
//
// Revision 1.2  2008/04/18 08:17:27  resoli
// Changed source file encoding to utf-8
//
// Revision 1.1  2004/12/27 11:14:32  resoli
// First release
//
// Revision 1.1  2004/12/23 15:34:05  resolicvs
// First release on remote CVS
//
// Revision 1.1  2004/12/23 17:58:48  resolicvs
// First release
//
// Revision 1.1  2004/12/23 13:52:13  resolicvs
// First release
//
// light version for use in j4sign 2004/12/20 - resoli
// eliminated dependencies from other ocf packages 
// see comments marked with ROB in source code.


// Revision 1.6  1999/04/07 15:20:31  breid
// load library fixed for native browser support
//
// Revision 1.5  1999/04/01 13:11:27  pbendel
// native browser support RFC-0005 (pbendel)
//
// Revision 1.4  1998/04/22 20:08:29  breid
// support for T0 implemented
//
// Revision 1.3  1998/04/14 16:16:46  breid
// htmldoc exception modified
//
// Revision 1.2  1998/04/09 13:40:53  breid
// *** empty log message ***
//
// Revision 1.1  1998/04/07 13:56:45  breid
// initial version
//
