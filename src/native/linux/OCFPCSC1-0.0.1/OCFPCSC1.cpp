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
 * Version: $Id: OCFPCSC1.cpp,v 1.7 1998/06/09 14:24:04 breid Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
//#include <windows.h>

#include "Tracer.h"
#include "PcscExceptions.h"
#include "PcscContexts.h"
#include "fieldIO.h"

#include "OCFPCSC1.h"

#include <winscard.h>


#define LPCTSTR LPCSTR

/*
 * Class:     com_ibm_opencard_terminal_pcsc10_OCFPCSC1
 * Method:    initTrace
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_ibm_opencard_terminal_pcsc10_OCFPCSC1_initTrace
  (JNIEnv *env, jobject obj) {

    //initTrace(env, obj);
}

/*
 * Class:     com_ibm_opencard_terminal_pcsc10_OCFPCSC1
 * Method:    SCardEstablishContext
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_opencard_terminal_pcsc10_OCFPCSC1_SCardEstablishContext
  (JNIEnv *env, jobject obj, jint scope) {

  CONTEXT_INFO cInfo;
  long returnCode;

  // clear ContextInformation
  clearContextInfo(&cInfo);

  returnCode = SCardEstablishContext((DWORD)scope, NULL, NULL, &cInfo.context);
  if (returnCode != SCARD_S_SUCCESS) {
    throwPcscException(env, obj, "SCardEstablishContext", "PC/SC Error SCardEstablishContext", returnCode);
  	return 0;
  }

  /* add this context to the internal table
   * it's useful in the case the layer above didn't release the context
   * the Dll_Main is able to release all established contexts
   */
  addContext(cInfo);

  return (jint)cInfo.context;
}


/*
 * Class:     com_ibm_opencard_terminal_pcsc10_OCFPCSC1
 * Method:    SCardReleaseContext
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_com_ibm_opencard_terminal_pcsc10_OCFPCSC1_SCardReleaseContext
  (JNIEnv *env, jobject obj, jint context) {

  long returnCode;

  if (isContextAvailable((long)context) < 0) {
	  throwPcscException(env, obj, "SCardReleaseContext", "tried to release a non-existing context",0);
  	return;
  }

  /* delete the context from the internal table */
  removeContext(context);

  returnCode = SCardReleaseContext((SCARDCONTEXT)context);
  if (returnCode != SCARD_S_SUCCESS) {
  	throwPcscException(env, obj, "SCardReleaseContext", "PC/SC Error SCardReleaseContext", returnCode);
	  return;
  }
  return;
}


/*
 * Class:     com_ibm_opencard_terminal_pcsc10_OCFPCSC1
 * Method:    SCardConnect
 * Signature: (ILjava/lang/String;IILjava/lang/Integer;)I
 */
JNIEXPORT jint JNICALL Java_com_ibm_opencard_terminal_pcsc10_OCFPCSC1_SCardConnect
  (JNIEnv *env, jobject obj, jint context, jstring jReader,
   jint jShareMode, jint jPreferredProtocol, jobject jActiveProtocol) {

  const char   *readerUTF;
  long	       cardHandle;
  DWORD        activeProtocol;
  int		       cPos;
  long	       returnCode;
  CONTEXT_INFO cInfo;

  /* check if context exists */
  if (cPos = isContextAvailable((long)context) < 0) {
    throwPcscException(env, obj, "SCardConnect", "PC/SC Wrapper Error: context not in table", 0);
    return 0;
  }

  // get contextInformationRecord
  cInfo = getContextInfoViaContext((SCARDCONTEXT)context);
  if (cInfo.context == 0) {
    throwPcscException(env, obj, "SCardConnect", "PC/SC Wrapper Error: couldn't get context information record", 0);
    return 0;
  }

  /* get the readers friendly name as 8bit code */
  readerUTF = env->GetStringUTFChars(jReader, NULL);

  /* get a connection to the card */
  returnCode = SCardConnect(  (SCARDCONTEXT)context,
                        			readerUTF,
				                      (DWORD)jShareMode,
				                      (DWORD)jPreferredProtocol,
				                      (LPSCARDHANDLE)&cardHandle,
				                      (DWORD *)&activeProtocol);

  /* release the readers friendly name */
  env->ReleaseStringUTFChars(jReader, readerUTF);

  if (returnCode != SCARD_S_SUCCESS) {
    throwPcscException(env, obj, "SCardConnect", "PC/SC Error SCardConnect", returnCode);
    return 0;
  }

  // store the cardHandle and the activeProtocol in the information record
  cInfo.cardHandle = cardHandle;
  cInfo.protocol = activeProtocol;

  // store the current context information
  if (setContextInformation(cInfo) != 0) {
    throwPcscException(env, obj, "SCardConnect", "PC/SC Wrapper Error: couldn't store context information record", 0);
    return 0;
  }

  return cardHandle;
}


/*
 * Class:     com_ibm_opencard_terminal_pcsc10_OCFPCSC1
 * Method:    SCardReconnect
 * Signature: (IIIILjava/lang/Integer;)V
 */
JNIEXPORT void JNICALL Java_com_ibm_opencard_terminal_pcsc10_OCFPCSC1_SCardReconnect
  (JNIEnv *env, jobject obj, jint card, jint shareMode,
   jint preferredProtocols, jint initialization, jobject jActiveProtocoll) {

  long	        returnCode;
  DWORD	        activeProtocol;
  CONTEXT_INFO  cInfo;

  // get the existing context informations
  cInfo = getContextInfoViaCardHandle((SCARDHANDLE)card);
  if (cInfo.context == 0) {
    throwPcscException(env, obj, "SCardReconnect", "PC/SC Wrapper Error: couldn't get context information record", 0);
    return;
  }

  /*
  returnCode = SCardReconnect((SCARDHANDLE)card,
		                        	(DWORD)shareMode,
			                        (DWORD)preferredProtocols,
                        			(DWORD)initialization,
			                        (LPDWORD)&activeProtocol);
  */

  if (returnCode != SCARD_S_SUCCESS) {
    throwPcscException(env, obj, "SCardReconnect", "PC/SC Error SCardReconnect", returnCode);
    return;
  }

  // update the protocol inside the information record
  cInfo.protocol = activeProtocol;

  // store the modified context informations
  if (setContextInformation(cInfo) != 0) {
    throwPcscException(env, obj, "SCardReconnect", "PC/SC Wrapper Error: update of context information record failed", 0);
    return;
  }

  return;
}


/*
 * Class:     com_ibm_opencard_terminal_pcsc10_OCFPCSC1
 * Method:    SCardDisconnect
 * Signature: (II)V
 */
JNIEXPORT void JNICALL Java_com_ibm_opencard_terminal_pcsc10_OCFPCSC1_SCardDisconnect
  (JNIEnv *env, jobject obj, jint card, jint disposition) {

  long          returnCode;
  CONTEXT_INFO  cInfo;

  // get the contextInfo from the table
  cInfo = getContextInfoViaCardHandle((SCARDHANDLE)card);
  if (cInfo.context == 0) {
    throwPcscException(env, obj, "SCardDisconnect", "PC/SC Wrapper Error: couldn't get context information record", 0);
    return;
  }

  returnCode = SCardDisconnect((SCARDHANDLE)card, (DWORD)disposition);
  if ((returnCode != SCARD_S_SUCCESS) && (returnCode != SCARD_W_REMOVED_CARD)) {
    throwPcscException(env, obj, "SCardDisconnect", "PC/SC Error SCardDisconnect", returnCode);
    return;
  }

  // delete cardHandle and active protocol in context info record
  cInfo.cardHandle = 0;
  cInfo.protocol = 0;

  // store the modified context informations
  if (setContextInformation(cInfo) != 0) {
    throwPcscException(env, obj, "SCardDisconnect", "PC/SC Wrapper Error: update of context information record failed", 0);
    return;
  }

  return;
}

/*
 * Class:     com_ibm_opencard_terminal_pcsc10_OCFPCSC1
 * Method:    SCardGetStatusChange
 * Signature: (II[Lcom/ibm/opencard/terminal/pcsc10/PcscReaderState;)V
 */
JNIEXPORT void JNICALL Java_com_ibm_opencard_terminal_pcsc10_OCFPCSC1_SCardGetStatusChange
  (JNIEnv *env, jobject obj, jint context, jint timeout, jobjectArray jReaderState) {

  SCARD_READERSTATE   *readerState;
  int         numReaderState;
  int         ii;
  long        returnCode;
  jobject     objReaderState;
  jbyteArray  jATR;

  /* First access the PcscReaderState structure to initialize the return       */
  /* value. Allocate a reader state array for each java ReaderState structure. */

  numReaderState = env->GetArrayLength(jReaderState);
  if (numReaderState < 1) {
    throwPcscException(env, obj, "SCardGetStatusChange",
                                 "size of ReaderState array must be greater than 0 elements", 0);
    return;
  }

  readerState = (SCARD_READERSTATE *)malloc(numReaderState * sizeof(SCARD_READERSTATE));
  if (readerState == NULL) {
    throwPcscException(env, obj, "SCardGetStatusChange", "error allocating memory for the readerState buffer", 0);
    return;
  }

  /* clear the allocated memory */
  memset(readerState, 0x00, numReaderState * sizeof(SCARD_READERSTATE));

  /* Now get each Java reader state structure and translate it into C++ */
  for (ii=0; ii<numReaderState; ii++) {
    objReaderState = env->GetObjectArrayElement(jReaderState, ii);
    if (env->ExceptionOccurred() != NULL) {
      free(readerState);
      throwPcscException(env, obj, "SCardGetStatusChange", "error getting elements from the readerState array", 0);
      return;
    }

    returnCode = getIntField(env, objReaderState, "CurrentState", (long *)&readerState[ii].dwCurrentState);
    if (returnCode) {
      free(readerState);
      throwPcscException(env, obj, "SCardGetStatusChange", "error getting CurrentState field from the readerState record", 0);
      return;
    }

    returnCode = getIntField(env, objReaderState, "EventState", (long*)&readerState[ii].dwEventState);
    if (returnCode) {
      free(readerState);
      throwPcscException(env, obj, "SCardGetStatusChange", "error getting EventState field from the readerState record", 0);
      return;
    }

    readerState[ii].szReader = (const char *)accessStringField(env, objReaderState, "Reader");
    if (readerState[ii].szReader == NULL) {
      free(readerState);
      throwPcscException(env, obj, "SCardGetStatusChange", "error getting Reader field from readerState record", 0);
      return;
    }

    int maxSize;
    returnCode = accessByteArray(env, objReaderState, "UserData", (unsigned char **)&readerState[ii].pvUserData, &maxSize);
    if (returnCode) {
      free(readerState);
      throwPcscException(env, obj, "SCardGetStatusChange", "error getting UserData field from readerState record", 0);
      return;
    }
  }

  /* set the response timeout to 1000ms */

  returnCode =  SCardGetStatusChange((SCARDCONTEXT)context, 1000, readerState, numReaderState);
  if (returnCode != SCARD_S_SUCCESS) {
    free(readerState);
    throwPcscException(env, obj, "SCardGetStatusChange", "error executing SCardGetStatusChange", returnCode);
    return;
  }

 readerState[0].dwCurrentState = readerState[0].dwEventState;

  /* write back the informations from the readerStatus to the java structures */
  for (ii=0; ii<numReaderState; ii++) {
    objReaderState = env->GetObjectArrayElement(jReaderState, ii);
    if (env->ExceptionOccurred() != NULL) {
      free(readerState);
      throwPcscException(env, obj, "SCardGetStatusChange", "error getting array elements", returnCode);
      return;
    }

    returnCode = setIntField(env, objReaderState, "EventState", readerState[ii].dwEventState);
    if (returnCode) {
      free(readerState);
      throwPcscException(env, obj, "SCardGetStatusChange", "error setting the EventState field", returnCode);
      return;
    }

    returnCode = releaseStringField(env, objReaderState, "Reader", (const char *)readerState[ii].szReader);
    if (returnCode) {
      free(readerState);
      throwPcscException(env, obj, "SCardGetStatusChange", "error setting the Reader field", returnCode);
      return;
    }

    returnCode = releaseByteArray(env, objReaderState, "UserData", (unsigned char *)readerState[ii].pvUserData);
    if (returnCode) {
      free(readerState);
      throwPcscException(env, obj, "SCardGetStatusChange", "error setting the UserData", returnCode);
      return;
    }

    // buffer for length of ATR
    jsize lenATR = (jsize)readerState[0].cbAtr;

    // check the length of the ATR in the PCSC ReaderState
    // if > 0 copy ATR to java ReaderState

    if (lenATR > 0) {

      // create new java bytearray with length of current ATR
      jATR = env->NewByteArray(lenATR);
      
      // copy PCSC ATR to jATR
      env->SetByteArrayRegion(jATR, 0, lenATR, (jbyte *)readerState[ii].rgbAtr);

      // find the ReaderState-Class
      jclass clsReaderState = env->GetObjectClass(objReaderState);

      // get the field ID from ATR-field
      jfieldID fldATR = env->GetFieldID(clsReaderState, "ATR", "[B");

      // set the ATR-field within the ReaderStateObject
      env->SetObjectField(objReaderState, fldATR, jATR);
    }
  }

  free(readerState);

  return;
}


/*
 * Class:     com_ibm_opencard_terminal_pcsc10_OCFPCSC1
 * Method:    SCardGetAttrib
 * Signature: (II)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_ibm_opencard_terminal_pcsc10_OCFPCSC1_SCardGetAttrib
  (JNIEnv *env, jobject obj, jint card, jint attrId) {

  long	returnCode;
  DWORD       lenAttr;
  jbyte       attrArray[36];
  jbyteArray  jAttrArray;


  /* length of temp buffer */
  lenAttr = 36;

  /* get the attribute information from the reader */
  /*
  returnCode = SCardGetAttrib((SCARDHANDLE)card,
                        			(DWORD)attrId,
			                        (LPBYTE)attrArray,
			                        (LPDWORD)&lenAttr);
  */

  if (returnCode != SCARD_S_SUCCESS) {
    throwPcscException(env, obj, "SCardGetAttrib", "error retrieving attribute data from reader", returnCode);
    return NULL;
  }

  /* allocate the jAttrArray with the returned length of the attribute data */
  jAttrArray = env->NewByteArray((jsize)lenAttr);
  if (jAttrArray == NULL) {
    throwPcscException(env, obj, "SCardGetAttrib", "error allocating the java bytearray for the attribute information", 0);
    return NULL;
  }

  /* copy the temp buffer into the java attribute array */
  env->SetByteArrayRegion(jAttrArray, (jsize)0, (jsize)lenAttr, attrArray);
  if (env->ExceptionOccurred() != NULL)
    return NULL;

  return jAttrArray;
}


/*
 * Class:     com_ibm_opencard_terminal_pcsc10_OCFPCSC1
 * Method:    SCardControl
 * Signature: (II[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_ibm_opencard_terminal_pcsc10_OCFPCSC1_SCardControl
  (JNIEnv *env, jobject obj, jint jCardHandle, jint jControlCode, jbyteArray jInBuffer) {

  LONG    returnCode;
  DWORD   lenInBuffer;
  DWORD   lenOutBuffer;
  DWORD   bytesReturned = 0;
  jbyte   *tmpInBuffer;			/* points to the java array*/
  jbyte   tmpOutBuffer[255];


  /* set the length of the buffers */
  lenInBuffer = env->GetArrayLength(jInBuffer);
  lenOutBuffer = 255;

  /* get the pointer to the internal buffer of the jInBuffer */
  if (lenInBuffer > 0)
    tmpInBuffer = env->GetByteArrayElements(jInBuffer, NULL);
  else
    tmpInBuffer = NULL;

  /*
  returnCode = SCardControl((SCARDHANDLE)jCardHandle,
		                  	    (DWORD)jControlCode,
			                      (LPCVOID)tmpInBuffer,
			                      (DWORD)lenInBuffer,
                  			    (LPVOID)tmpOutBuffer,
			                      (DWORD)lenOutBuffer,
                   			    &bytesReturned);
  */

  if (returnCode != SCARD_S_SUCCESS) {
    throwPcscException(env, obj, "SCardControl", "error occured", returnCode);
    return NULL;
  }

  /* return buffer control to java vm without internal update */
  env->ReleaseByteArrayElements(jInBuffer, tmpInBuffer, JNI_ABORT);

  /* create java byte array for the returned data */
  jbyteArray jOutBuffer = env->NewByteArray((jsize)bytesReturned);
  if (jOutBuffer == NULL) {
    throwPcscException(env, obj, "SCardControl", "panic: couldn't create java byte array", returnCode);
    return NULL;
  }

  /* get the pointer to the internal byte buffer */
  jbyte   *ptr;
  ptr = env->GetByteArrayElements(jOutBuffer, NULL);
  if (ptr == NULL) {
    throwPcscException(env, obj, "SCardControl",
     	"panic: couldn't get pointer to the internal buffer of the java byte array", returnCode);
    return NULL;
  }

  /* copy the read data to the new java byte array */
  memcpy((void *)ptr, (void *)tmpOutBuffer, (size_t)bytesReturned);

  /* return buffer control to java vm */
  env->ReleaseByteArrayElements(jOutBuffer, ptr, 0);

  /* return the data */
  return jOutBuffer;
}

/*
 * Class:     com_ibm_opencard_terminal_pcsc10_OCFPCSC1
 * Method:    SCardListReaders
 * Signature: (Ljava/lang/String;)[Ljava/lang/String;
 */
JNIEXPORT jobjectArray JNICALL Java_com_ibm_opencard_terminal_pcsc10_OCFPCSC1_SCardListReaders
  (JNIEnv *env, jobject obj, jstring groups) {

  SCARDCONTEXT hContext;
  long	    returnCode;
  DWORD	    lenReaderList;
  char	    *readerList;
  jobjectArray    readerArray;

  /* get a pointer to the converted 8bit-version of the groups string */
  const char *groupsUTF;
  groupsUTF = (groups != NULL) ? env->GetStringUTFChars(groups, NULL) : NULL;

  SCardEstablishContext(SCARD_SCOPE_SYSTEM, 0, 0, &hContext);

  /* first retrieve the length of the readerlist */
  /* the first parameter <context> is not needed. query is not directed to a specific context */
  returnCode = SCardListReaders(hContext, 0, NULL, &lenReaderList);

  // got the right length of the ReaderStr?
  if (returnCode != SCARD_S_SUCCESS) {
    env->ReleaseStringUTFChars(groups, groupsUTF);
    throwPcscException(env, obj, "SCardListReaders", "error getting length of reader list",returnCode);
    SCardReleaseContext(hContext);
    return NULL;
  }

  /* allocate space for the reader list */
  readerList = (char *)malloc((size_t)lenReaderList + 1);

  /* the first parameter <context> is not needed. query is not directed to a specific context */
  returnCode = SCardListReaders(hContext, 0, readerList, &lenReaderList);

  SCardReleaseContext(hContext);

  if (returnCode != SCARD_S_SUCCESS) {
    free(readerList);
    throwPcscException(env, obj, "SCardListReaders", "error getting length of readerlist",returnCode);
    return NULL;
  }

  // The reader names are null terminated strings packed one
  // after another into the buffer. Separate them, making each into
  // a Java string. pack the strings into an array and return the array.

  // count names ....

  int ii;
  int jj;
  int numNames;
  for (ii=0, numNames=0; ii<lenReaderList; ) {
    numNames++;
    ii += strlen(&readerList[ii])+1;
    if (strlen(&readerList[ii]) == 0) 
      ii++;    // series ended by 2 NULLs
  }

  if (numNames == 0) return NULL;

  // make object array of proper size .....

  readerArray = env->NewObjectArray(numNames,env->FindClass("java/lang/String"),NULL);
  if (readerArray==NULL) {
    free(readerList);
    throwPcscException(env, obj, "SCardListReaders", "error converting reader list to array", 0);
    return NULL;
  }

  // make java strings and put them in array ...

  for (ii=0, jj=0; jj<numNames; jj++) {
    char       *name;
    jstring    jname;

    name = &readerList[ii];
    jname = env->NewStringUTF(name);
    if (jname==NULL) {
      free(readerList);
      throwPcscException(env, obj, "SCardListReaders", "error converting reader list to array", 0);
      return NULL;
    }

    env->SetObjectArrayElement(readerArray, jj, jname);
    if (env->ExceptionOccurred() != NULL) {
  	  free(readerList);
	    throwPcscException(env, obj, "SCardListReaders", "error writing to reader array", 0);
	    return NULL;
    }

    ii += strlen(name)+1;
  }

  free(readerList);

  /* 8bit-string not longer needed */
  env->ReleaseStringUTFChars(groups, groupsUTF);

  return readerArray;
}


/*
 * Class:     com_ibm_opencard_terminal_pcsc10_OCFPCSC1
 * Method:    SCardTransmit
 * Signature: (I[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_ibm_opencard_terminal_pcsc10_OCFPCSC1_SCardTransmit
  (JNIEnv *env, jobject obj, jint jCard, jbyteArray jSendBuf) {

  SCARD_IO_REQUEST    sendPci;
  SCARD_IO_REQUEST    recvPci;

  long		            returnCode;

  DWORD		            lenSendBuf;
  jbyte		            *ptrSendBuf;

  jbyteArray		      jRecvBuf;
  DWORD		            lenRecvBuf;
  jbyte		            tmpRecvBuf[512];

  CONTEXT_INFO        cInfo;

  // get the contextInfo from the table (checks the active protocol of the card connection)
  cInfo = getContextInfoViaCardHandle((SCARDHANDLE)jCard);
  if (cInfo.context == 0) {
    throwPcscException(env, obj, "SCardTransmit", "PC/SC Wrapper Error: couldn't get context information record", 0);
    return NULL;
  }

  // check for cardHandle 
  if (cInfo.cardHandle == 0) {
    throwPcscException(env, obj, "SCardTransmit", "PC/SC Wrapper Error: tried to transmit data without connection to the card", 0);
    return NULL;
  }

  // setup io request record
  switch(cInfo.protocol) {
    
    case SCARD_PROTOCOL_T0:
    case SCARD_PROTOCOL_T1:
    case SCARD_PROTOCOL_RAW:
      sendPci.dwProtocol = cInfo.protocol;
      sendPci.cbPciLength = sizeof(SCARD_IO_REQUEST);
      recvPci.dwProtocol = cInfo.protocol;
      recvPci.cbPciLength = sizeof(SCARD_IO_REQUEST);
      break;

    default:
      throwPcscException(env, obj, "SCardTransmit", "PC/SC Wrapper Error: no active or unknown protocol on connection", 0);
      return NULL;
  }

  /* get the size of the sendbuf */
  lenSendBuf = env->GetArrayLength(jSendBuf);

  if (lenSendBuf > 0) {

    /* get the pointer to the send buf */
    ptrSendBuf = env->GetByteArrayElements(jSendBuf, NULL);

    if (ptrSendBuf == NULL) {
  	  throwPcscException(env, obj, "SCardTransmit", "error getting ptr to java sendbuffer", 0);
	    return NULL;
    }
  } else
    ptrSendBuf = NULL;

  lenRecvBuf = sizeof(tmpRecvBuf);

  /* transmit the data */
  returnCode = SCardTransmit((SCARDHANDLE)jCard,
			                       (LPSCARD_IO_REQUEST)&sendPci,(LPCBYTE)ptrSendBuf, lenSendBuf,
                    			   (LPSCARD_IO_REQUEST)&recvPci,(LPBYTE)tmpRecvBuf,&lenRecvBuf);

  if (returnCode != SCARD_S_SUCCESS) {
    throwPcscException(env, obj, "SCardTransmit", "error occurred with SCardTransmit", returnCode);
    return NULL;
  }

  /* create the java receiveBuffer and copy the data into the new array */
  jRecvBuf = env->NewByteArray((jsize)lenRecvBuf);
  env->SetByteArrayRegion(jRecvBuf, (jsize)0, (jsize)lenRecvBuf, tmpRecvBuf);
  if (env->ExceptionOccurred() != NULL)
    return NULL;

  return jRecvBuf;
}




// $Log: OCFPCSC1.cpp,v $
// Revision 1.7  1998/06/09 14:24:04  breid
// SCardGetStatusChange: ATR-field added
//
// Revision 1.6  1998/04/23 09:13:18  breid
// SCardTransmit: receiveBuffer enlarged
//
// Revision 1.5  1998/04/22 20:08:29  breid
// support for T0 implemented
//
// Revision 1.4  1998/04/21 08:31:17  breid
// Error handling modified
//
