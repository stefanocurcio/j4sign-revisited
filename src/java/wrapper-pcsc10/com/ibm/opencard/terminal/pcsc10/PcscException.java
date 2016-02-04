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

/**
 * <tt>PcscException</tt> is thrown when any type of error occurs in the
 * PCSC-Interface.
 *
 * The PCSC return code is provided as exception data.
 *
 * @authod  Stephan Breideneich (sbreiden@de.ibm.com)
 * @version $Id: PcscException.java,v 1.3 2011/01/13 07:34:02 resoli Exp $
 */

public class PcscException extends Exception {

  /**
   * Constructor accepting a message text
   *
   * @param   msg - exception message
   */
  public PcscException(String s) {
    super(s); rc=0;
  }

  /**
   * Constructor accepting a message text and the PCSC return code.
   *
   * @param   msg - exception message
   * @param   retCode - the PCSC return code.
   * @see     PcscConstants
   */
  public PcscException(String msg, int retCode) {
    super(msg);
    rc = retCode;
  }

  /**
   * provides application with PCSC return code.
   *
   * @return  PCSC return code.
   */
  public int returnCode() {
    return rc;
  }

  private int rc;
}

// $Log: PcscException.java,v $
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
// Revision 1.2  1998/04/07 12:40:48  breid
// *** empty log message ***
//
// Revision 1.1  1998/04/07 11:32:25  breid
// initial version
//
