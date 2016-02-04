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
 * Version: $Id: PcscContexts.cpp,v 1.2 1998/04/22 20:08:31 breid Exp $
 */

#include <stdio.h>
#include <memory.h>
#include "PcscContexts.h"


/* this array holds the established context informations */
CONTEXT_INFO establishedContexts[MAX_CONTEXTS];

/*
 * clearContextInfo
 *
 * clears the given context information record
 */
void clearContextInfo(CONTEXT_INFO *cInfo) {
  memset((void *)cInfo, 0, sizeof(CONTEXT_INFO));
}


/*
 * initContextTable
 *
 * clears the internal table
 */
void initContextTable() {
  /* initial cleanup of the establishedContexts array */
  int i;
  CONTEXT_INFO cInfo;

  clearContextInfo(&cInfo);

  for (i=0; i<MAX_CONTEXTS; i++)
    establishedContexts[i] = cInfo;
}


/*
 * isContextAvailable
 *
 * checks if the given context is available in establishedContexts table
 *
 * return  < 0 - context not in use
 * return >= 0 - context in use. returncode gives the position within the array establishedContexts
 */
int isContextAvailable(SCARDCONTEXT context) {
  for (int i=0 ; i < MAX_CONTEXTS ; i++)
    if (establishedContexts[i].context == context)
      return i; // context found

  return -1;    // context not found
}


/*
 * isCardHandleAvailable
 *
 * checks if the given cardHandle is available in establishedContexts table
 *
 * return  < 0 - cardHandle not in use
 * return >= 0 - cardHandle in use. returncode gives the position within the table establishedContexts
 */
int isCardHandleAvailable(SCARDHANDLE cardHandle) {
  for (int i=0 ; i < MAX_CONTEXTS ; i++)
    if (establishedContexts[i].cardHandle == cardHandle)
      return i; // cardHandle found

  return -1;    // cardHandle not found
}					       /* end of isContextAvailable*/


/*
 * getContextInfoViaContext
 *
 * returns the context information record of a given context
 *
 * return CONTEXT_INFO with .context = 0: contextInformation not found
 * return CONTEXT_INFO
 */
CONTEXT_INFO getContextInfoViaContext(SCARDCONTEXT context) {
  int cPos;
  CONTEXT_INFO cInfo;

  // clear buffer
  clearContextInfo(&cInfo);

  // which element in the table?
  if ((cPos = isContextAvailable(context)) < 0)
    return cInfo; // cInfo is empty at this point

  return establishedContexts[cPos];
}


/*
 * getContextInfoViaCardHandle
 *
 * returns the context information record of a given cardHandle
 *
 * return CONTEXT_INFO with .context = 0: contextInformation not found
 * return CONTEXT_INFO
 */
CONTEXT_INFO getContextInfoViaCardHandle(SCARDHANDLE cardHandle) {
  int cPos;
  CONTEXT_INFO cInfo;

  // clear buffer
  clearContextInfo(&cInfo);

  // which element in the table?
  if ((cPos = isCardHandleAvailable(cardHandle)) < 0)
    return cInfo; // cInfo is empty at this point

  return establishedContexts[cPos];
}					    /* end of getContextInformation*/


/*
 * setContextInformation
 *
 * set the context information record for the context
 * the position of the record depends on the context-value inside the record
 *
 * return  0 = ok
 * return -1 = failed
 */
int setContextInformation(CONTEXT_INFO cInfo) {
  int cPos;

  // Is the context stored in the table?
  if ((cPos = isContextAvailable(cInfo.context)) < 0)
    return -1; // failed

  // store the information record at the same position
  establishedContexts[cPos] = cInfo;

  return 0; // information stored
}


/*
 * addContext
 *
 * adds a context to the internal table establishedContext
 *
 * return   -1 - failed
 * return >= 0 - position of the context in the table
 */
int addContext(CONTEXT_INFO cInfo) {
  int freePos;

  // where is a free element in the establishedContexts array (context == 0)?
  for (freePos=0 ;freePos < MAX_CONTEXTS; freePos++ )
    if (establishedContexts[freePos].context == 0) {
      establishedContexts[freePos] = cInfo;
      return freePos;
    }

  // addContext failed
  return -1;
}						       /* end of addContext*/


/*
 * removeContext
 *
 * removes the given context from the internal table establishedContext
 *
 * return   -1 - given context not found
 * return  = 0 - ok
 */
int removeContext(SCARDCONTEXT context) {
  for (int freePos; freePos < MAX_CONTEXTS; freePos++)
    if (establishedContexts[freePos].context == context) {
      clearContextInfo(&establishedContexts[freePos]);
      return 0;
    }

  // given context not found
  return -1;
}						    /* end of removeContext*/


/*
 * removeAllContexts
 *
 * removes all registered contexts
 */
void removeAllContexts() {
  for (int i; i < MAX_CONTEXTS; i++) 
	  clearContextInfo(&establishedContexts[i]);

  return;
}						/* end of removeAllContexts*/

// $Log: PcscContexts.cpp,v $
// Revision 1.2  1998/04/22 20:08:31  breid
// support for T0 implemented
//
// Revision 1.1  1998/04/07 11:36:05  breid
// initial version.
//
