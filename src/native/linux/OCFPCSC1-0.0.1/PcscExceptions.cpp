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
 * Version: $Id: PcscExceptions.cpp,v 1.1 1998/04/07 13:52:34 breid Exp $
 */


#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <jni.h>

#include "Tracer.h"
#include "PcscExceptions.h"

/*
 * throwPcscException
 *
 * throws an PcscException with the return code informations of the PC/SC
 * the exception information is posted to the tracer
 *
 * return: 0 for success, other values for exception occured
 */
int throwPcscException(JNIEnv *env, jobject obj,
		       const char *method, const char *msg, long returnCode) {

    jstring     exceptionMsg;
    jclass      exceptionClass;
    jobject     exceptionInstance;
    jmethodID   constructorID;

    char	*completeMsg;

    exceptionClass = env->FindClass(PCSC_EXCEPTION_CLASS);
    if (exceptionClass == NULL)
	return -1;

    constructorID = env->GetMethodID(exceptionClass,
			    "<init>", "(Ljava/lang/String;I)V");
    if (constructorID == NULL)
	return -1;

    /* allocate enough bufferspace for the complete exception message */
    completeMsg = (char *)malloc(strlen(method) + strlen(msg) + 50);
    sprintf(completeMsg, "PCSC Exception in method %s: %s\n" \
	    "return code = %8.8x\n", method, msg,returnCode);

    if ((exceptionMsg = env->NewStringUTF(completeMsg)) == NULL) {
	free(completeMsg);
	return -1;
    }

    free(completeMsg);

    exceptionInstance = env->NewObject(exceptionClass, constructorID,
			    exceptionMsg, (jint) returnCode);
    if (exceptionInstance == NULL)
	return -1;

    /* and now try to display the exception with the trace method */
    Trace(env, obj, TRACE_ERROR, method, msg);

    if (env->Throw((jthrowable)exceptionInstance))
	return -1;

    return 0;
}

// $Log: PcscExceptions.cpp,v $
// Revision 1.1  1998/04/07 13:52:34  breid
// initial version.
//
