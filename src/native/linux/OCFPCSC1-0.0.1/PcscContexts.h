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

/*
 * Author:  Stephan Breideneich (sbreiden@de.ibm.com)
 * Version: $Id: PcscContexts.h,v 1.2 1998/04/22 20:08:32 breid Exp $
 */

#include <jni.h>
#include <winscard.h>


#define MAX_CONTEXTS 10		   /* defines the maximum count of contexts*/


/* this structure stores the established context with its additional informations */
typedef struct {
  SCARDCONTEXT context;
  SCARDHANDLE  cardHandle;
  DWORD	       protocol;
} CONTEXT_INFO;


/*
 * clearContextInfo
 *
 * clears the given context information record
 */
void clearContextInfo(CONTEXT_INFO *cInfo);


/*
 * initContextTable
 *
 * clears the internal context information table
 */
void initContextTable();


/*
 * isContextAvailable
 *
 * checks if the given context is available in establishedContexts array
 *
 * return  < 0 - context not in use
 * return >= 0 - context in use. returncode gives the position within the array establishedContexts
 */
int isContextAvailable(SCARDCONTEXT context);


/*
 * isCardHandleAvailable
 *
 * checks if the given cardHandle is available in establishedContexts table
 *
 * return  < 0 - cardHandle not in use
 * return >= 0 - cardHandle in use. returncode gives the position within the table establishedContexts
 */
int isCardHandleAvailable(SCARDHANDLE cardHandle);


/*
 * getContextInfoViaContext
 *
 * returns the context information record of a given context
 *
 * return CONTEXT_INFO with .context = 0: contextInformation not found
 * return CONTEXT_INFO
 */
CONTEXT_INFO getContextInfoViaContext(SCARDCONTEXT context);


/*
 * getContextInfoViaCardHandle
 *
 * returns the context information record of a given cardHandle
 *
 * return CONTEXT_INFO with .context = 0: contextInformation not found
 * return CONTEXT_INFO
 */
CONTEXT_INFO getContextInfoViaCardHandle(SCARDHANDLE cardHandle);


/*
 * setContextInformation
 *
 * set the context information record for the context
 * the position of the record depends on the context-value inside the record
 *
 * return  0 = ok
 * return -1 = failed
 */
int setContextInformation(CONTEXT_INFO cInfo);


/*
 * addContext
 *
 * adds a context informatin record to the internal table establishedContext
 *
 * return   -1 - failed
 * return >= 0 - position of the context in the table
 */
int addContext(CONTEXT_INFO cInfo);


/*
 * removeContext
 *
 * removes the given context from the internal table establishedContext
 *
 * return   -1 - given context not found
 * return  = 0 - ok
 */
int removeContext(SCARDCONTEXT context);


/*
 * removeAllContexts
 *
 * removes all registered contexts
 */
void removeAllContexts();

// $Log: PcscContexts.h,v $
// Revision 1.2  1998/04/22 20:08:32  breid
// support for T0 implemented
//
// Revision 1.1  1998/04/07 11:36:15  breid
// initial version.
//

