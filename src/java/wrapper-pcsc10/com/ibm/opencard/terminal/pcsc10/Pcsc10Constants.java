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

/** Defines some constants used by PCSC terminals.
 *
 * @author  Stephan Breideneich (sbreiden@de.ibm.com)
 * @version $Id: Pcsc10Constants.java,v 1.3 2011/01/13 07:34:02 resoli Exp $
 */
public interface Pcsc10Constants {

  /* necessary subset of the PCSC constants */
  final static int SCARD_S_SUCCESS		          = 0x00000000;

  final static int SCARD_E_INVALID_HANDLE	      = 0x80100003;
  final static int SCARD_E_INVALID_PARAMETER	  = 0x80100004;
  final static int SCARD_E_NOT_READY		        = 0x80100010;
  final static int SCARD_E_INVALID_VALUE	      = 0x80100011;
  final static int SCARD_E_TIMEOUT		          = 0x8010000A;
  final static int SCARD_E_NO_MEMORY		        = 0x80100006;
  final static int SCARD_E_UNSUPPORTED_REQUEST  = 0xA0100001;

  final static int SCARD_W_UNRESPONSIVE_CARD	  = 0x80100066;
  final static int SCARD_W_UNPOWERED_CARD	      = 0x80100067;
  final static int SCARD_W_RESET_CARD		        = 0x80100068;
  final static int SCARD_W_REMOVED_CARD		      = 0x80100069;

  /* Access Mode Flags */
  final static int SCARD_SHARE_EXCLUSIVE	      = 1;
  final static int SCARD_SHARE_DIRECT		        = 3;

  /* Protocol Identifier Bits */
  final static int SCARD_PROTOCOL_T0		        = 0x00000001;
  final static int SCARD_PROTOCOL_T1		        = 0x00000002;
  final static int SCARD_PROTOCOL_RAW           = 0x00010000;
  final static int SCARD_PROTOCOL_DEFAULT       = 0x80000000;  // Use implicit PTS.
  final static int SCARD_PROTOCOL_OPTIMAL       = 0x00000000; 

  /* Card Disposition    */
  final static int SCARD_LEAVE_CARD		          = 0;
  final static int SCARD_RESET_CARD		          = 1;
  final static int SCARD_UNPOWER_CARD		        = 2;
  final static int SCARD_EJECT_CARD		          = 3;

  /* Card Reader State   */
  final static int SCARD_STATE_UNAWARE		      = 0x00000000;
  final static int SCARD_STATE_IGNORE		        = 0x00000001;
  final static int SCARD_STATE_CHANGED		      = 0x00000002;
  final static int SCARD_STATE_UNKNOWN		      = 0x00000004;
  final static int SCARD_STATE_UNAVAILABLE	    = 0x00000008;
  final static int SCARD_STATE_EMPTY		        = 0x00000010;
  final static int SCARD_STATE_PRESENT		      = 0x00000020;

  final static int SCARD_ABSENT			            = 1;
  final static int SCARD_PRESENT		            = 2;
  final static int SCARD_POWERED		            = 4;

  /* Context Scope       */
  final static int SCARD_SCOPE_USER		          = 0;

  /* Attributes */
  final static int SCARD_ATTR_VENDOR_NAME	      = 0x00010100;
  final static int SCARD_ATTR_VENDOR_IFD_TYPE   = 0x00010101;
  final static int SCARD_ATTR_VENDOR_IFD_VERSION= 0x00010102;
  final static int SCARD_ATTR_ATR_STRING	      = 0x00090303;
  final static int SCARD_ATTR_ICC_PRESENCE	    = 0x00090300;
}

// $Log: Pcsc10Constants.java,v $
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
// Revision 1.3  1999/10/22 07:31:14  pbendel
// RFC 17-1 Terminal locking mechanism using lock handle
//
// Revision 1.2  1998/04/22 20:08:31  breid
// support for T0 implemented
//
// Revision 1.1  1998/04/07 12:44:00  breid
// initial version
//
